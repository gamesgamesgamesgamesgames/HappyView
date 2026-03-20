use wasmtime::*;

/// Default fuel for plugin execution (≈100ms CPU time)
pub const DEFAULT_FUEL: u64 = 10_000_000;

/// WASM runtime for executing plugins
pub struct WasmRuntime {
    engine: Engine,
}

impl WasmRuntime {
    pub fn new() -> Result<Self, anyhow::Error> {
        let mut config = Config::new();
        config.async_support(true);
        config.consume_fuel(true);

        let engine = Engine::new(&config)?;

        Ok(Self { engine })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Compile a WASM module
    pub fn compile(&self, wasm_bytes: &[u8]) -> Result<Module, anyhow::Error> {
        Module::new(&self.engine, wasm_bytes)
    }
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create WASM runtime")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuel_constant_value() {
        // 10M fuel ≈ 100ms CPU time per spec
        assert_eq!(DEFAULT_FUEL, 10_000_000);
    }

    #[test]
    fn test_runtime_has_fuel_enabled() {
        let runtime = WasmRuntime::new().expect("Failed to create runtime");
        // We can verify fuel is enabled by checking we can set it on a store
        let mut store = wasmtime::Store::new(runtime.engine(), ());
        assert!(store.set_fuel(1000).is_ok());
    }

    #[test]
    fn test_compile_invalid_wasm_fails() {
        let runtime = WasmRuntime::new().expect("Failed to create runtime");
        let result = runtime.compile(b"not valid wasm");
        assert!(result.is_err());
    }
}
