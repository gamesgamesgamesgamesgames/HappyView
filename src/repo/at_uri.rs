use crate::error::AppError;

/// Extract the DID from an AT URI (at://did/collection/rkey).
#[allow(dead_code)]
pub(crate) fn parse_did_from_at_uri(uri: &str) -> Result<String, AppError> {
    let stripped = uri
        .strip_prefix("at://")
        .ok_or_else(|| AppError::Internal("AT URI must start with at://".into()))?;

    stripped
        .split('/')
        .next()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Internal("invalid AT URI".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_did_from_valid_at_uri() {
        let did = parse_did_from_at_uri("at://did:plc:abc123/app.bsky.feed.post/3k2bqxyz").unwrap();
        assert_eq!(did, "did:plc:abc123");
    }

    #[test]
    fn parse_did_from_uri_with_no_rkey() {
        let did = parse_did_from_at_uri("at://did:plc:abc123/collection").unwrap();
        assert_eq!(did, "did:plc:abc123");
    }

    #[test]
    fn parse_did_from_did_web_uri() {
        let did = parse_did_from_at_uri("at://did:web:example.com/collection/rkey").unwrap();
        assert_eq!(did, "did:web:example.com");
    }

    #[test]
    fn parse_did_from_uri_missing_prefix() {
        let result = parse_did_from_at_uri("did:plc:abc123/collection/rkey");
        assert!(result.is_err());
    }
}
