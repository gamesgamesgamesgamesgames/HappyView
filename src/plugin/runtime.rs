use wasmtime::*;

/// WASM runtime for executing plugins
pub struct WasmRuntime {
    engine: Engine,
}

impl WasmRuntime {
    pub fn new() -> Result<Self, anyhow::Error> {
        let mut config = Config::new();
        config.async_support(true);

        let engine = Engine::new(&config)?;

        Ok(Self { engine })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create WASM runtime")
    }
}
