// src/plugin/executor.rs

use crate::db::DatabaseBackend;
use crate::lexicon::LexiconRegistry;
use crate::plugin::host::{PluginState, register_host_functions};
use crate::plugin::memory::{
    PluginEnvelopeError, PluginResponse, dealloc_guest, read_from_guest, write_to_guest,
};
use crate::plugin::runtime::{DEFAULT_FUEL, WasmRuntime};
use crate::plugin::{ExternalProfile, PluginInfo, PluginRegistry, SyncRecord, TokenSet};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use wasmtime::{Instance, Linker, Memory, Store, TypedFunc};

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),

    #[error("WASM instantiation failed: {0}")]
    Instantiation(#[source] anyhow::Error),

    #[error("Memory allocation failed")]
    MemoryAllocation,

    #[error("Plugin function trapped: {0}")]
    Trap(#[source] wasmtime::Error),

    #[error("Invalid response from plugin: {0}")]
    InvalidResponse(String),

    #[error("Plugin returned error: {code} - {message}")]
    PluginError {
        code: String,
        message: String,
        retryable: bool,
    },

    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("Timeout (fuel exhausted)")]
    Timeout,

    #[error("Missing export: {0}")]
    MissingExport(String),
}

impl From<PluginEnvelopeError> for ExecutionError {
    fn from(e: PluginEnvelopeError) -> Self {
        ExecutionError::PluginError {
            code: e.code,
            message: e.message,
            retryable: e.retryable,
        }
    }
}

/// Single-use wrapper around a WASM instance
#[allow(dead_code)]
pub struct PluginInstance {
    pub(crate) store: Store<PluginState>,
    pub(crate) instance: Instance,
    pub(crate) memory: Memory,
    pub(crate) alloc: TypedFunc<u32, u32>,
    pub(crate) dealloc: TypedFunc<(u32, u32), ()>,
}

impl PluginInstance {
    /// Call plugin_info() - no input required
    pub async fn call_plugin_info(&mut self) -> Result<PluginInfo, ExecutionError> {
        let func = self
            .instance
            .get_typed_func::<(), i64>(&mut self.store, "plugin_info")
            .map_err(|_| ExecutionError::MissingExport("plugin_info".into()))?;

        self.store
            .set_fuel(DEFAULT_FUEL)
            .map_err(ExecutionError::Trap)?;

        let packed = func
            .call_async(&mut self.store, ())
            .await
            .map_err(Self::classify_error)?;

        // Unpack i64: upper 32 bits = ptr, lower 32 bits = len
        let ptr = (packed >> 32) as u32;
        let len = (packed & 0xFFFFFFFF) as u32;

        let bytes =
            read_from_guest(&self.store, ptr, len).map_err(|_| ExecutionError::MemoryAllocation)?;

        dealloc_guest(&mut self.store, ptr, len)
            .await
            .map_err(|_| ExecutionError::MemoryAllocation)?;

        let response: PluginResponse<PluginInfo> = serde_json::from_slice(&bytes)
            .map_err(|e| ExecutionError::InvalidResponse(e.to_string()))?;

        response.into_result().map_err(ExecutionError::from)
    }

    /// Call get_authorize_url(state, redirect_uri, config)
    pub async fn call_get_authorize_url(
        &mut self,
        state: &str,
        redirect_uri: &str,
        config: &serde_json::Value,
    ) -> Result<String, ExecutionError> {
        let input = serde_json::json!({
            "state": state,
            "redirect_uri": redirect_uri,
            "config": config
        });
        self.call_plugin_function("get_authorize_url", &input).await
    }

    /// Call handle_callback with all callback parameters
    ///
    /// For OAuth2: params contains "code" and "state"
    /// For OpenID 2.0: params contains "openid.claimed_id", "openid.identity", etc.
    pub async fn call_handle_callback(
        &mut self,
        params: &HashMap<String, String>,
        config: &serde_json::Value,
    ) -> Result<TokenSet, ExecutionError> {
        // Build input with all params flattened at the top level
        let mut input = serde_json::Map::new();
        for (k, v) in params {
            input.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        input.insert("config".to_string(), config.clone());

        self.call_plugin_function("handle_callback", &serde_json::Value::Object(input))
            .await
    }

    /// Call refresh_tokens(refresh_token, config)
    pub async fn call_refresh_tokens(
        &mut self,
        refresh_token: &str,
        config: &serde_json::Value,
    ) -> Result<TokenSet, ExecutionError> {
        let input = serde_json::json!({
            "refresh_token": refresh_token,
            "config": config
        });
        self.call_plugin_function("refresh_tokens", &input).await
    }

    /// Call get_profile(access_token, config)
    pub async fn call_get_profile(
        &mut self,
        access_token: &str,
        config: &serde_json::Value,
    ) -> Result<ExternalProfile, ExecutionError> {
        let input = serde_json::json!({
            "access_token": access_token,
            "config": config
        });
        self.call_plugin_function("get_profile", &input).await
    }

    /// Call sync_account(access_token, config)
    pub async fn call_sync_account(
        &mut self,
        access_token: &str,
        config: &serde_json::Value,
    ) -> Result<Vec<SyncRecord>, ExecutionError> {
        let input = serde_json::json!({
            "access_token": access_token,
            "config": config
        });
        self.call_plugin_function("sync_account", &input).await
    }

    /// Generic helper for plugin functions with input and typed output
    async fn call_plugin_function<T: serde::de::DeserializeOwned>(
        &mut self,
        name: &str,
        input: &serde_json::Value,
    ) -> Result<T, ExecutionError> {
        let input_bytes = serde_json::to_vec(input)
            .map_err(|e| ExecutionError::InvalidResponse(e.to_string()))?;

        let func = self
            .instance
            .get_typed_func::<(u32, u32), i64>(&mut self.store, name)
            .map_err(|_| ExecutionError::MissingExport(name.into()))?;

        self.store
            .set_fuel(DEFAULT_FUEL)
            .map_err(ExecutionError::Trap)?;

        let (input_ptr, input_len) = write_to_guest(&mut self.store, &input_bytes)
            .await
            .map_err(|_| ExecutionError::MemoryAllocation)?;

        let packed = func
            .call_async(&mut self.store, (input_ptr, input_len))
            .await
            .map_err(Self::classify_error)?;

        // Unpack i64: upper 32 bits = ptr, lower 32 bits = len
        let ptr = (packed >> 32) as u32;
        let len = (packed & 0xFFFFFFFF) as u32;

        let bytes =
            read_from_guest(&self.store, ptr, len).map_err(|_| ExecutionError::MemoryAllocation)?;

        dealloc_guest(&mut self.store, ptr, len)
            .await
            .map_err(|_| ExecutionError::MemoryAllocation)?;

        let response: PluginResponse<T> = serde_json::from_slice(&bytes)
            .map_err(|e| ExecutionError::InvalidResponse(e.to_string()))?;

        response.into_result().map_err(ExecutionError::from)
    }

    /// Classify a wasmtime error as Timeout or Trap
    fn classify_error(e: wasmtime::Error) -> ExecutionError {
        if e.to_string().contains("fuel") {
            ExecutionError::Timeout
        } else {
            ExecutionError::Trap(e)
        }
    }
}

/// Factory for creating plugin instances
pub struct PluginExecutor {
    runtime: Arc<WasmRuntime>,
    registry: Arc<PluginRegistry>,
    db: sqlx::AnyPool,
    db_backend: DatabaseBackend,
    http_client: reqwest::Client,
    lexicons: Arc<LexiconRegistry>,
}

impl PluginExecutor {
    pub fn new(
        runtime: Arc<WasmRuntime>,
        registry: Arc<PluginRegistry>,
        db: sqlx::AnyPool,
        db_backend: DatabaseBackend,
        http_client: reqwest::Client,
        lexicons: Arc<LexiconRegistry>,
    ) -> Self {
        Self {
            runtime,
            registry,
            db,
            db_backend,
            http_client,
            lexicons,
        }
    }

    /// Instantiate a plugin with the given scope
    pub async fn instantiate(
        &self,
        plugin_id: &str,
        scope: &str,
        secrets: HashMap<String, String>,
        config: serde_json::Value,
    ) -> Result<PluginInstance, ExecutionError> {
        // Get plugin from registry
        let plugin = self
            .registry
            .get(plugin_id)
            .await
            .ok_or_else(|| ExecutionError::PluginNotFound(plugin_id.to_string()))?;

        // Compile module
        let module = self
            .runtime
            .compile(&plugin.wasm_bytes)
            .map_err(ExecutionError::Instantiation)?;

        // Create linker with host functions
        let mut linker = Linker::new(self.runtime.engine());
        register_host_functions(&mut linker).map_err(ExecutionError::Instantiation)?;

        // Create store with initial state (memory/alloc/dealloc set to None)
        // Note: db is Option<sqlx::AnyPool> in PluginState
        let state = PluginState {
            plugin_id: plugin_id.to_string(),
            scope: scope.to_string(),
            secrets,
            config,
            db: Some(self.db.clone()),
            db_backend: self.db_backend,
            http_client: self.http_client.clone(),
            lexicons: self.lexicons.clone(),
            usage: Default::default(),
            memory: None,
            alloc: None,
            dealloc: None,
        };

        let mut store = Store::new(self.runtime.engine(), state);
        store
            .set_fuel(DEFAULT_FUEL)
            .map_err(ExecutionError::Instantiation)?;

        // Instantiate module
        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .map_err(ExecutionError::Instantiation)?;

        // Get memory export
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| ExecutionError::MissingExport("memory".into()))?;

        // Get alloc/dealloc exports
        let alloc = instance
            .get_typed_func::<u32, u32>(&mut store, "alloc")
            .map_err(|_| ExecutionError::MissingExport("alloc".into()))?;
        let dealloc = instance
            .get_typed_func::<(u32, u32), ()>(&mut store, "dealloc")
            .map_err(|_| ExecutionError::MissingExport("dealloc".into()))?;

        // Store memory/alloc/dealloc in state
        store.data_mut().memory = Some(memory);
        store.data_mut().alloc = Some(alloc.clone());
        store.data_mut().dealloc = Some(dealloc.clone());

        Ok(PluginInstance {
            store,
            instance,
            memory,
            alloc,
            dealloc,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_error_plugin_not_found() {
        let err = ExecutionError::PluginNotFound("steam".into());
        assert!(err.to_string().contains("steam"));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_execution_error_timeout() {
        let err = ExecutionError::Timeout;
        assert!(
            err.to_string().to_lowercase().contains("timeout") || err.to_string().contains("fuel")
        );
    }

    #[test]
    fn test_plugin_error_conversion() {
        let plugin_err = PluginEnvelopeError {
            code: "AUTH_FAILED".into(),
            message: "Bad token".into(),
            retryable: true,
        };
        let exec_err: ExecutionError = plugin_err.into();
        match exec_err {
            ExecutionError::PluginError {
                code,
                message,
                retryable,
            } => {
                assert_eq!(code, "AUTH_FAILED");
                assert_eq!(message, "Bad token");
                assert!(retryable);
            }
            _ => panic!("Wrong error variant"),
        }
    }

    #[test]
    fn test_all_error_variants_have_display() {
        let errors: Vec<ExecutionError> = vec![
            ExecutionError::PluginNotFound("test".into()),
            ExecutionError::MemoryAllocation,
            ExecutionError::InvalidResponse("bad json".into()),
            ExecutionError::ResourceLimit("too many requests".into()),
            ExecutionError::Timeout,
            ExecutionError::MissingExport("plugin_info".into()),
        ];
        for err in errors {
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn test_plugin_executor_new_signature() {
        // Verify PluginExecutor::new exists with expected signature (compile-time check)
        fn _check_signature(
            _runtime: std::sync::Arc<crate::plugin::WasmRuntime>,
            _registry: std::sync::Arc<crate::plugin::PluginRegistry>,
            _db: sqlx::AnyPool,
            _db_backend: crate::db::DatabaseBackend,
            _http_client: reqwest::Client,
            _lexicons: std::sync::Arc<crate::lexicon::LexiconRegistry>,
        ) -> PluginExecutor {
            PluginExecutor::new(
                _runtime,
                _registry,
                _db,
                _db_backend,
                _http_client,
                _lexicons,
            )
        }
    }

    #[test]
    fn test_plugin_instance_struct_exists() {
        // Verify PluginInstance struct has expected fields (compile-time check)
        fn _check_fields(instance: PluginInstance) {
            let _ = instance.store;
            let _ = instance.instance;
            let _ = instance.memory;
            let _ = instance.alloc;
            let _ = instance.dealloc;
        }
    }

    #[test]
    fn test_plugin_instance_has_expected_methods() {
        // Compile-time check that methods exist with expected signatures
        fn _check_call_plugin_info<'a>(
            inst: &'a mut PluginInstance,
        ) -> impl std::future::Future<Output = Result<crate::plugin::PluginInfo, ExecutionError>> + 'a
        {
            inst.call_plugin_info()
        }

        fn _check_call_get_authorize_url<'a>(
            inst: &'a mut PluginInstance,
            state: &'a str,
            redirect_uri: &'a str,
            config: &'a serde_json::Value,
        ) -> impl std::future::Future<Output = Result<String, ExecutionError>> + 'a {
            inst.call_get_authorize_url(state, redirect_uri, config)
        }

        fn _check_call_handle_callback<'a>(
            inst: &'a mut PluginInstance,
            params: &'a HashMap<String, String>,
            config: &'a serde_json::Value,
        ) -> impl std::future::Future<Output = Result<crate::plugin::TokenSet, ExecutionError>> + 'a
        {
            inst.call_handle_callback(params, config)
        }

        fn _check_call_refresh_tokens<'a>(
            inst: &'a mut PluginInstance,
            refresh_token: &'a str,
            config: &'a serde_json::Value,
        ) -> impl std::future::Future<Output = Result<crate::plugin::TokenSet, ExecutionError>> + 'a
        {
            inst.call_refresh_tokens(refresh_token, config)
        }

        fn _check_call_get_profile<'a>(
            inst: &'a mut PluginInstance,
            access_token: &'a str,
            config: &'a serde_json::Value,
        ) -> impl std::future::Future<Output = Result<crate::plugin::ExternalProfile, ExecutionError>> + 'a
        {
            inst.call_get_profile(access_token, config)
        }

        fn _check_call_sync_account<'a>(
            inst: &'a mut PluginInstance,
            access_token: &'a str,
            config: &'a serde_json::Value,
        ) -> impl std::future::Future<Output = Result<Vec<crate::plugin::SyncRecord>, ExecutionError>> + 'a
        {
            inst.call_sync_account(access_token, config)
        }
    }
}
