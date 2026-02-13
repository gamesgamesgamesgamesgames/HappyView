use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Serialize)]
pub struct Profile {
    pub did: String,
    pub handle: String,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "avatarURL", skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidDocument {
    #[serde(default)]
    also_known_as: Vec<String>,
    #[serde(default)]
    service: Vec<DidService>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidService {
    id: String,
    service_endpoint: String,
}

#[derive(Deserialize)]
struct GetRecordResponse {
    value: serde_json::Value,
}

/// Resolve a full profile for the given DID: DID document -> handle + PDS -> profile record.
pub async fn resolve_profile(
    http: &reqwest::Client,
    plc_url: &str,
    did: &str,
) -> Result<Profile, AppError> {
    let did_doc = resolve_did_document(http, plc_url, did).await?;

    let handle = did_doc
        .also_known_as
        .iter()
        .find_map(|uri| uri.strip_prefix("at://"))
        .map(|h| h.to_string());

    let pds_endpoint = did_doc
        .service
        .iter()
        .find(|s| s.id == "#atproto_pds")
        .map(|s| s.service_endpoint.clone())
        .ok_or_else(|| AppError::NotFound("no PDS endpoint in DID document".into()))?;

    let (display_name, description, avatar_url) = fetch_profile_from_pds(http, &pds_endpoint, did)
        .await
        .unwrap_or((None, None, None));

    Ok(Profile {
        did: did.to_string(),
        handle: handle.unwrap_or_else(|| did.to_string()),
        display_name,
        description,
        avatar_url,
    })
}

/// Resolve the PDS endpoint for a DID by fetching its DID document.
pub async fn resolve_pds_endpoint(
    http: &reqwest::Client,
    plc_url: &str,
    did: &str,
) -> Result<String, AppError> {
    let did_doc = resolve_did_document(http, plc_url, did).await?;

    did_doc
        .service
        .iter()
        .find(|s| s.id == "#atproto_pds")
        .map(|s| s.service_endpoint.clone())
        .ok_or_else(|| AppError::NotFound("no PDS endpoint in DID document".into()))
}

/// Fetch a DID document from the PLC directory.
// TODO: handle did:web:* resolution (fetch https://{domain}/.well-known/did.json)
async fn resolve_did_document(
    http: &reqwest::Client,
    plc_url: &str,
    did: &str,
) -> Result<DidDocument, AppError> {
    let url = format!("{}/{did}", plc_url.trim_end_matches('/'));

    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("DID resolution failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(AppError::NotFound(format!(
            "DID document not found for {did}"
        )));
    }

    resp.json()
        .await
        .map_err(|e| AppError::Internal(format!("invalid DID document: {e}")))
}

/// Fetch the `app.bsky.actor.profile` record from the user's PDS and extract
/// displayName, description, and avatar URL.
async fn fetch_profile_from_pds(
    http: &reqwest::Client,
    pds_endpoint: &str,
    did: &str,
) -> Result<(Option<String>, Option<String>, Option<String>), AppError> {
    let url = format!(
        "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=app.bsky.actor.profile&rkey=self",
        pds_endpoint.trim_end_matches('/'),
        did,
    );

    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("PDS request failed: {e}")))?;

    if !resp.status().is_success() {
        return Ok((None, None, None));
    }

    let record: GetRecordResponse = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("invalid PDS response: {e}")))?;

    let value = &record.value;

    let display_name = value
        .get("displayName")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let description = value
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let avatar_url = value
        .get("avatar")
        .and_then(|avatar| avatar.get("ref"))
        .and_then(|r| r.get("$link"))
        .and_then(|link| link.as_str())
        .map(|cid| {
            format!(
                "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
                pds_endpoint.trim_end_matches('/'),
                did,
                cid,
            )
        });

    Ok((display_name, description, avatar_url))
}
