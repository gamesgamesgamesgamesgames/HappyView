use serde_json::Value;
use std::collections::HashSet;

/// Recursively walk a JSON value and collect all string values starting with "at://".
pub fn extract_at_uris(value: &Value) -> HashSet<String> {
    let mut uris = HashSet::new();
    collect_at_uris(value, &mut uris);
    uris
}

fn collect_at_uris(value: &Value, uris: &mut HashSet<String>) {
    match value {
        Value::String(s) => {
            if s.starts_with("at://") {
                uris.insert(s.clone());
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_at_uris(item, uris);
            }
        }
        Value::Object(obj) => {
            for v in obj.values() {
                collect_at_uris(v, uris);
            }
        }
        _ => {}
    }
}

/// Update record_refs for a given source record.
/// Deletes old refs and inserts new ones.
pub async fn sync_refs(
    db: &sqlx::PgPool,
    source_uri: &str,
    collection: &str,
    record: &Value,
) -> Result<(), sqlx::Error> {
    let uris = extract_at_uris(record);

    // Delete existing refs for this source
    sqlx::query("DELETE FROM record_refs WHERE source_uri = $1")
        .bind(source_uri)
        .execute(db)
        .await?;

    // Insert new refs
    for target_uri in &uris {
        sqlx::query(
            "INSERT INTO record_refs (source_uri, target_uri, collection) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING"
        )
        .bind(source_uri)
        .bind(target_uri)
        .bind(collection)
        .execute(db)
        .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_top_level_uri() {
        let val = json!({"subject": "at://did:plc:abc/com.example/123"});
        let uris = extract_at_uris(&val);
        assert_eq!(uris.len(), 1);
        assert!(uris.contains("at://did:plc:abc/com.example/123"));
    }

    #[test]
    fn extracts_nested_uri() {
        let val = json!({"outer": {"inner": "at://did:plc:abc/col/rkey"}});
        let uris = extract_at_uris(&val);
        assert_eq!(uris.len(), 1);
        assert!(uris.contains("at://did:plc:abc/col/rkey"));
    }

    #[test]
    fn extracts_uris_from_arrays() {
        let val = json!({"refs": ["at://did:plc:a/col/1", "at://did:plc:b/col/2"]});
        let uris = extract_at_uris(&val);
        assert_eq!(uris.len(), 2);
    }

    #[test]
    fn ignores_non_at_strings() {
        let val = json!({"url": "https://example.com", "name": "test"});
        let uris = extract_at_uris(&val);
        assert!(uris.is_empty());
    }

    #[test]
    fn empty_object_returns_empty() {
        let uris = extract_at_uris(&json!({}));
        assert!(uris.is_empty());
    }

    #[test]
    fn deduplicates_repeated_uris() {
        let val = json!({"a": "at://did:plc:x/c/1", "b": "at://did:plc:x/c/1"});
        let uris = extract_at_uris(&val);
        assert_eq!(uris.len(), 1);
    }
}
