use atrium_identity::handle::DnsTxtResolver;
use hickory_resolver::TokioResolver;

/// Native DNS TXT resolver using system DNS configuration.
/// Implements atrium's `DnsTxtResolver` trait for use with `AtprotoHandleResolver`,
/// and provides a `lookup_txt` method for direct TXT record queries.
#[derive(Clone)]
pub struct NativeDnsResolver {
    resolver: TokioResolver,
}

impl Default for NativeDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeDnsResolver {
    pub fn new() -> Self {
        Self {
            resolver: TokioResolver::builder_tokio()
                .expect("Failed to read system DNS config")
                .build(),
        }
    }

    /// Look up TXT records for a given name, returning all record values.
    pub async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, String> {
        let response = self
            .resolver
            .txt_lookup(name)
            .await
            .map_err(|e| format!("DNS TXT lookup failed for {name}: {e}"))?;

        Ok(response.iter().map(|txt| txt.to_string()).collect())
    }
}

impl DnsTxtResolver for NativeDnsResolver {
    async fn resolve(
        &self,
        query: &str,
    ) -> core::result::Result<Vec<String>, Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.lookup_txt(query).await.map_err(|e| {
            Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error + Send + Sync>
        })
    }
}
