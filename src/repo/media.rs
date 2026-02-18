use serde_json::{Value, json};

/// Walk `media[]` and add a `url` field to each blob so the frontend can
/// display images directly.
#[allow(dead_code)]
pub(crate) fn enrich_media_blobs(record: &mut Value, pds: &str, did: &str) {
    let media = match record.get_mut("media").and_then(|m| m.as_array_mut()) {
        Some(arr) => arr,
        None => return,
    };

    let pds_base = pds.trim_end_matches('/');

    for item in media.iter_mut() {
        let cid = item
            .get("blob")
            .and_then(|b| b.get("ref"))
            .and_then(|r| r.get("$link"))
            .and_then(|l| l.as_str())
            .map(|s| s.to_string());

        if let Some(cid) = cid
            && let Some(blob) = item.get_mut("blob")
            && let Some(obj) = blob.as_object_mut()
        {
            obj.insert(
                "url".to_string(),
                json!(format!(
                    "{pds_base}/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}"
                )),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrich_media_adds_url() {
        let mut record = json!({
            "media": [{
                "blob": {
                    "ref": { "$link": "bafyreiabc" },
                    "mimeType": "image/jpeg",
                    "size": 1024
                }
            }]
        });

        enrich_media_blobs(&mut record, "https://pds.example.com", "did:plc:test");

        let url = record["media"][0]["blob"]["url"].as_str().unwrap();
        assert_eq!(
            url,
            "https://pds.example.com/xrpc/com.atproto.sync.getBlob?did=did:plc:test&cid=bafyreiabc"
        );
    }

    #[test]
    fn enrich_media_noop_without_media() {
        let mut record = json!({"title": "test"});
        enrich_media_blobs(&mut record, "https://pds.example.com", "did:plc:test");
        assert!(record.get("media").is_none());
    }

    #[test]
    fn enrich_media_skips_items_without_ref() {
        let mut record = json!({
            "media": [{
                "blob": { "mimeType": "image/png" }
            }]
        });

        enrich_media_blobs(&mut record, "https://pds.example.com", "did:plc:test");
        assert!(record["media"][0]["blob"].get("url").is_none());
    }

    #[test]
    fn enrich_media_handles_multiple_items() {
        let mut record = json!({
            "media": [
                { "blob": { "ref": { "$link": "cid1" } } },
                { "blob": { "ref": { "$link": "cid2" } } }
            ]
        });

        enrich_media_blobs(&mut record, "https://pds.example.com/", "did:plc:x");

        let url1 = record["media"][0]["blob"]["url"].as_str().unwrap();
        let url2 = record["media"][1]["blob"]["url"].as_str().unwrap();
        assert!(url1.contains("cid1"));
        assert!(url2.contains("cid2"));
    }

    #[test]
    fn enrich_media_trims_trailing_slash() {
        let mut record = json!({
            "media": [{
                "blob": { "ref": { "$link": "bafytest" } }
            }]
        });

        enrich_media_blobs(&mut record, "https://pds.example.com/", "did:plc:test");

        let url = record["media"][0]["blob"]["url"].as_str().unwrap();
        assert!(url.starts_with("https://pds.example.com/xrpc/"));
        assert!(!url.contains("//xrpc"));
    }
}
