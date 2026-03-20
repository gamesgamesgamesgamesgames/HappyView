use super::HostContext;

/// Get a secret value by name (from pre-loaded secrets map)
pub fn get_secret(ctx: &HostContext, name: &str) -> Option<String> {
    ctx.secrets.get(name).cloned()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    #[test]
    fn test_get_existing_secret() {
        let mut secrets: HashMap<String, String> = HashMap::new();
        secrets.insert("API_KEY".to_string(), "abc123".to_string());
        assert_eq!(secrets.get("API_KEY").cloned(), Some("abc123".to_string()));
    }

    #[test]
    fn test_get_missing_secret() {
        let secrets: HashMap<String, String> = HashMap::new();
        assert_eq!(secrets.get("MISSING").cloned(), None);
    }

    #[test]
    fn test_get_secret_case_sensitive() {
        let mut secrets: HashMap<String, String> = HashMap::new();
        secrets.insert("api_key".to_string(), "lower".to_string());
        // Keys are case-sensitive
        assert_eq!(secrets.get("API_KEY").cloned(), None);
        assert_eq!(secrets.get("api_key").cloned(), Some("lower".to_string()));
    }
}
