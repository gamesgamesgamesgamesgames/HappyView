use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AppState;
use crate::auth::XrpcClaims;
use crate::db::{adapt_sql, now_rfc3339};
use crate::error::AppError;
use crate::spaces::types::*;
use crate::spaces::{SpaceUri, db, members};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSpaceInput {
    type_nsid: String,
    skey: String,
    display_name: Option<String>,
    description: Option<String>,
    access_mode: Option<AccessMode>,
    managing_app_did: Option<String>,
    config: Option<SpaceConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpaceUriQuery {
    space_uri: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListSpacesQuery {
    owner_did: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteSpaceInput {
    space_uri: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateSpaceInput {
    space_uri: String,
    display_name: Option<Option<String>>,
    description: Option<Option<String>>,
    access_mode: Option<AccessMode>,
    app_allowlist: Option<Option<Vec<String>>>,
    app_denylist: Option<Option<Vec<String>>>,
    managing_app_did: Option<Option<String>>,
    config: Option<SpaceConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutRecordInput {
    space_uri: String,
    collection: String,
    rkey: String,
    record: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteRecordInput {
    space_uri: String,
    collection: String,
    rkey: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetRecordQuery {
    space_uri: String,
    collection: String,
    rkey: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListRecordsQuery {
    space_uri: String,
    collection: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddMemberInput {
    space_uri: String,
    member_did: String,
    access: Option<SpaceAccess>,
    is_delegation: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveMemberInput {
    space_uri: String,
    member_did: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateInviteInput {
    space_uri: String,
    access: Option<SpaceAccess>,
    max_uses: Option<i64>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RedeemInviteInput {
    token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeInviteInput {
    space_uri: String,
    invite_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetCredentialInput {
    space_uri: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshCredentialInput {
    space_uri: String,
    credential: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WriteNotificationInput {
    space_uri: String,
    author_did: String,
    collection: String,
    rkey: String,
    action: crate::spaces::notifications::WriteAction,
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

const NS: &str = "dev.happyview";

pub fn space_routes() -> Router<AppState> {
    Router::new()
        // Space CRUD
        .route(&format!("/xrpc/{NS}.space.create"), post(create_space))
        .route(&format!("/xrpc/{NS}.space.get"), get(get_space))
        .route(&format!("/xrpc/{NS}.space.list"), get(list_spaces))
        .route(&format!("/xrpc/{NS}.space.delete"), post(delete_space))
        .route(&format!("/xrpc/{NS}.space.update"), post(update_space))
        // Records
        .route(&format!("/xrpc/{NS}.space.putRecord"), post(put_record))
        .route(
            &format!("/xrpc/{NS}.space.deleteRecord"),
            post(delete_record),
        )
        .route(&format!("/xrpc/{NS}.space.getRecord"), get(get_record))
        .route(&format!("/xrpc/{NS}.space.listRecords"), get(list_records))
        // Members
        .route(&format!("/xrpc/{NS}.space.listMembers"), get(list_members))
        .route(&format!("/xrpc/{NS}.space.addMember"), post(add_member))
        .route(
            &format!("/xrpc/{NS}.space.removeMember"),
            post(remove_member),
        )
        // Invites
        .route(
            &format!("/xrpc/{NS}.space.invite.create"),
            post(create_invite),
        )
        .route(
            &format!("/xrpc/{NS}.space.invite.redeem"),
            post(redeem_invite),
        )
        .route(
            &format!("/xrpc/{NS}.space.invite.revoke"),
            post(revoke_invite),
        )
        .route(&format!("/xrpc/{NS}.space.invite.list"), get(list_invites))
        // Credentials
        .route(
            &format!("/xrpc/{NS}.space.getCredential"),
            post(get_credential),
        )
        .route(
            &format!("/xrpc/{NS}.space.refreshCredential"),
            post(refresh_credential),
        )
        // Notifications
        .route(
            &format!("/xrpc/{NS}.space.writeNotification"),
            post(write_notification),
        )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn require_auth(claims: &XrpcClaims) -> Result<&crate::auth::Claims, AppError> {
    claims
        .0
        .as_ref()
        .ok_or_else(|| AppError::Auth("This endpoint requires DPoP authentication".into()))
}

async fn resolve_space(state: &AppState, space_uri: &str) -> Result<Space, AppError> {
    let uri = SpaceUri::parse(space_uri)?;
    db::get_space_by_address(
        &state.db,
        state.db_backend,
        &uri.owner_did,
        &uri.type_nsid,
        &uri.skey,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Space not found".into()))
}

async fn require_space_admin(state: &AppState, space: &Space, did: &str) -> Result<(), AppError> {
    if space.owner_did == did {
        return Ok(());
    }
    let sql = adapt_sql("SELECT is_super FROM users WHERE did = ?", state.db_backend);
    let row: Option<(i32,)> = sqlx::query_as(&sql)
        .bind(did)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("failed to check admin status: {e}")))?;
    if row.is_some_and(|(is_super,)| is_super != 0) {
        return Ok(());
    }
    Err(AppError::Forbidden(
        "Only the space owner can perform this action".into(),
    ))
}

fn extract_space_credential(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-space-credential")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

async fn require_membership(
    state: &AppState,
    space: &Space,
    did: &str,
    require_write: bool,
    space_credential: Option<&str>,
) -> Result<SpaceAccess, AppError> {
    if let Some(token) = space_credential {
        let space_uri = format!(
            "ats://{}/{}/{}",
            space.owner_did, space.type_nsid, space.skey
        );
        match crate::spaces::credential::verify_external_credential(
            token,
            &state.http,
            &state.config.plc_url,
        )
        .await
        {
            Ok(claims) if claims.space == space_uri => {
                let access = match claims.scope.as_str() {
                    "write" => SpaceAccess::Write,
                    _ => SpaceAccess::Read,
                };
                if require_write && !access.can_write() {
                    return Err(AppError::Forbidden(
                        "Write access is required for this action".into(),
                    ));
                }
                return Ok(access);
            }
            Ok(_) => {
                // Credential is valid but for a different space — fall through
            }
            Err(_) => {
                // External verification failed — fall through to local check
            }
        }
    }

    let access = members::is_member(&state.db, state.db_backend, &space.id, did)
        .await?
        .ok_or_else(|| AppError::Forbidden("You are not a member of this space".into()))?;
    if require_write && !access.can_write() {
        return Err(AppError::Forbidden(
            "Write access is required for this action".into(),
        ));
    }
    Ok(access)
}

fn content_cid(record: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(record).unwrap_or_default();
    let hash = Sha256::digest(&bytes);
    format!("bafyrei{}", hex::encode(&hash[..20]))
}

// ---------------------------------------------------------------------------
// Space CRUD handlers
// ---------------------------------------------------------------------------

async fn create_space(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<CreateSpaceInput>,
) -> Result<Response, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let did = claims.did().to_string();

    if input.type_nsid.is_empty() || input.skey.is_empty() {
        return Err(AppError::BadRequest(
            "type_nsid and skey are required".into(),
        ));
    }

    let existing = db::get_space_by_address(
        &state.db,
        state.db_backend,
        &did,
        &input.type_nsid,
        &input.skey,
    )
    .await?;
    if existing.is_some() {
        return Err(AppError::Conflict(
            "A space with this address already exists".into(),
        ));
    }

    let space = Space {
        id: Uuid::new_v4().to_string(),
        owner_did: did.clone(),
        type_nsid: input.type_nsid,
        skey: input.skey,
        display_name: input.display_name,
        description: input.description,
        access_mode: input.access_mode.unwrap_or(AccessMode::DefaultAllow),
        app_allowlist: None,
        app_denylist: None,
        managing_app_did: input.managing_app_did,
        config: input.config.unwrap_or_default(),
        created_at: now_rfc3339(),
        updated_at: now_rfc3339(),
    };

    db::create_space(&state.db, state.db_backend, &space).await?;

    // Auto-add the creator as a write member
    let member = SpaceMember {
        id: Uuid::new_v4().to_string(),
        space_id: space.id.clone(),
        member_did: did.clone(),
        access: SpaceAccess::Write,
        is_delegation: false,
        granted_by: Some(did),
        created_at: now_rfc3339(),
    };
    db::add_member(&state.db, state.db_backend, &member).await?;

    let space_uri = format!(
        "ats://{}/{}/{}",
        space.owner_did, space.type_nsid, space.skey
    );
    let body = serde_json::json!({
        "spaceUri": space_uri,
        "space": space,
    });

    let mut response = Json(body).into_response();
    *response.status_mut() = StatusCode::CREATED;
    Ok(response)
}

async fn get_space(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Query(query): Query<SpaceUriQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let space = resolve_space(&state, &query.space_uri).await?;

    // If the space's membership is not public, require auth + membership
    if !space.config.membership_public {
        let claims = require_auth(&xrpc_claims)?;
        let did = claims.did();
        if space.owner_did != did {
            members::is_member(&state.db, state.db_backend, &space.id, did)
                .await?
                .ok_or_else(|| AppError::NotFound("Space not found".into()))?;
        }
    }

    let space_uri = format!(
        "ats://{}/{}/{}",
        space.owner_did, space.type_nsid, space.skey
    );
    Ok(Json(serde_json::json!({
        "spaceUri": space_uri,
        "space": space,
    })))
}

async fn list_spaces(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Query(query): Query<ListSpacesQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let did = claims.did().to_string();

    let owner = query.owner_did.as_deref().unwrap_or(&did);
    let spaces = db::list_spaces_by_owner(&state.db, state.db_backend, owner).await?;

    let spaces_with_uris: Vec<serde_json::Value> = spaces
        .into_iter()
        .map(|s| {
            let uri = format!("ats://{}/{}/{}", s.owner_did, s.type_nsid, s.skey);
            serde_json::json!({ "spaceUri": uri, "space": s })
        })
        .collect();

    Ok(Json(serde_json::json!({ "spaces": spaces_with_uris })))
}

async fn delete_space(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<DeleteSpaceInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let space = resolve_space(&state, &input.space_uri).await?;
    require_space_admin(&state, &space, claims.did()).await?;

    db::delete_space(&state.db, state.db_backend, &space.id).await?;

    Ok(Json(serde_json::json!({ "success": true })))
}

async fn update_space(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<UpdateSpaceInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let mut space = resolve_space(&state, &input.space_uri).await?;
    require_space_admin(&state, &space, claims.did()).await?;

    if let Some(name) = input.display_name {
        space.display_name = name;
    }
    if let Some(desc) = input.description {
        space.description = desc;
    }
    if let Some(mode) = input.access_mode {
        space.access_mode = mode;
    }
    if let Some(list) = input.app_allowlist {
        space.app_allowlist = list;
    }
    if let Some(list) = input.app_denylist {
        space.app_denylist = list;
    }
    if let Some(did) = input.managing_app_did {
        space.managing_app_did = did;
    }
    if let Some(config) = input.config {
        space.config = config;
    }

    db::update_space(&state.db, state.db_backend, &space).await?;

    let space_uri = format!(
        "ats://{}/{}/{}",
        space.owner_did, space.type_nsid, space.skey
    );
    Ok(Json(serde_json::json!({
        "spaceUri": space_uri,
        "space": space,
    })))
}

// ---------------------------------------------------------------------------
// Record handlers
// ---------------------------------------------------------------------------

async fn put_record(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    headers: HeaderMap,
    Json(input): Json<PutRecordInput>,
) -> Result<Response, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let did = claims.did().to_string();
    let space = resolve_space(&state, &input.space_uri).await?;
    let cred = extract_space_credential(&headers);
    require_membership(&state, &space, &did, true, cred.as_deref()).await?;

    let cid = content_cid(&input.record);
    let record_uri = format!(
        "ats://{}/{}/{}/{}/{}/{}",
        space.owner_did, space.type_nsid, space.skey, did, input.collection, input.rkey
    );

    let record = SpaceRecord {
        uri: record_uri.clone(),
        space_id: space.id,
        author_did: did,
        collection: input.collection,
        rkey: input.rkey,
        record: input.record,
        cid: cid.clone(),
        indexed_at: now_rfc3339(),
    };

    db::upsert_space_record(&state.db, state.db_backend, &record).await?;

    let body = serde_json::json!({
        "uri": record_uri,
        "cid": cid,
    });

    let mut response = Json(body).into_response();
    *response.status_mut() = StatusCode::CREATED;
    Ok(response)
}

async fn delete_record(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<DeleteRecordInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let did = claims.did().to_string();
    let space = resolve_space(&state, &input.space_uri).await?;

    let record_uri = format!(
        "ats://{}/{}/{}/{}/{}/{}",
        space.owner_did, space.type_nsid, space.skey, did, input.collection, input.rkey
    );

    let record = db::get_space_record(&state.db, state.db_backend, &record_uri).await?;
    match record {
        Some(r) if r.author_did != did => {
            return Err(AppError::Forbidden(
                "You can only delete your own records".into(),
            ));
        }
        None => {
            return Err(AppError::NotFound("Record not found".into()));
        }
        _ => {}
    }

    db::delete_space_record(&state.db, state.db_backend, &record_uri).await?;

    Ok(Json(serde_json::json!({ "success": true })))
}

async fn get_record(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    headers: HeaderMap,
    Query(query): Query<GetRecordQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let space = resolve_space(&state, &query.space_uri).await?;
    let cred = extract_space_credential(&headers);
    require_membership(&state, &space, claims.did(), false, cred.as_deref()).await?;

    let record = db::get_space_record_by_parts(
        &state.db,
        state.db_backend,
        &space.id,
        &query.collection,
        &query.rkey,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Record not found".into()))?;

    Ok(Json(serde_json::json!({
        "uri": record.uri,
        "space": query.space_uri,
        "collection": record.collection,
        "record": record.record,
        "cid": record.cid,
    })))
}

async fn list_records(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    headers: HeaderMap,
    Query(query): Query<ListRecordsQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let space = resolve_space(&state, &query.space_uri).await?;
    let cred = extract_space_credential(&headers);
    require_membership(&state, &space, claims.did(), false, cred.as_deref()).await?;

    let limit = query.limit.unwrap_or(50).min(100);
    let records = db::list_space_records(
        &state.db,
        state.db_backend,
        &space.id,
        query.collection.as_deref(),
        limit,
        query.cursor.as_deref(),
    )
    .await?;

    let cursor = records.last().map(|r| r.indexed_at.clone());

    let records_json: Vec<serde_json::Value> = records
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "uri": r.uri,
                "space": query.space_uri,
                "collection": r.collection,
                "record": r.record,
                "cid": r.cid,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "records": records_json,
        "cursor": cursor,
    })))
}

// ---------------------------------------------------------------------------
// Member handlers
// ---------------------------------------------------------------------------

async fn list_members(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    headers: HeaderMap,
    Query(query): Query<SpaceUriQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let space = resolve_space(&state, &query.space_uri).await?;

    if !space.config.membership_public {
        let claims = require_auth(&xrpc_claims)?;
        let cred = extract_space_credential(&headers);
        require_membership(&state, &space, claims.did(), false, cred.as_deref()).await?;
    }

    let resolved = members::resolve_members(&state.db, state.db_backend, &space.id).await?;

    Ok(Json(serde_json::json!({ "members": resolved })))
}

async fn add_member(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<AddMemberInput>,
) -> Result<Response, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let space = resolve_space(&state, &input.space_uri).await?;
    require_space_admin(&state, &space, claims.did()).await?;

    let existing =
        db::get_member(&state.db, state.db_backend, &space.id, &input.member_did).await?;
    if existing.is_some() {
        return Err(AppError::Conflict(
            "Member already exists in this space".into(),
        ));
    }

    let member = SpaceMember {
        id: Uuid::new_v4().to_string(),
        space_id: space.id,
        member_did: input.member_did,
        access: input.access.unwrap_or(SpaceAccess::Read),
        is_delegation: input.is_delegation.unwrap_or(false),
        granted_by: Some(claims.did().to_string()),
        created_at: now_rfc3339(),
    };

    db::add_member(&state.db, state.db_backend, &member).await?;

    let mut response = Json(serde_json::json!({ "member": member })).into_response();
    *response.status_mut() = StatusCode::CREATED;
    Ok(response)
}

async fn remove_member(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<RemoveMemberInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let space = resolve_space(&state, &input.space_uri).await?;
    require_space_admin(&state, &space, claims.did()).await?;

    let removed =
        db::remove_member(&state.db, state.db_backend, &space.id, &input.member_did).await?;

    if !removed {
        return Err(AppError::NotFound("Member not found in this space".into()));
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

// ---------------------------------------------------------------------------
// Invite handlers
// ---------------------------------------------------------------------------

async fn create_invite(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<CreateInviteInput>,
) -> Result<Response, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let space = resolve_space(&state, &input.space_uri).await?;
    require_space_admin(&state, &space, claims.did()).await?;

    let mut token_bytes = [0u8; 24];
    rand::Fill::fill(&mut token_bytes, &mut rand::rng());
    let token = hex::encode(token_bytes);
    let token_hash = hex::encode(Sha256::digest(token.as_bytes()));

    let invite = SpaceInvite {
        id: Uuid::new_v4().to_string(),
        space_id: space.id,
        token_hash,
        created_by: claims.did().to_string(),
        access: input.access.unwrap_or(SpaceAccess::Read),
        max_uses: input.max_uses,
        uses: 0,
        expires_at: input.expires_at,
        revoked: false,
        created_at: now_rfc3339(),
    };

    db::create_invite(&state.db, state.db_backend, &invite).await?;

    let mut response = Json(serde_json::json!({
        "inviteId": invite.id,
        "token": token,
        "access": invite.access,
        "maxUses": invite.max_uses,
        "expiresAt": invite.expires_at,
    }))
    .into_response();
    *response.status_mut() = StatusCode::CREATED;
    Ok(response)
}

async fn redeem_invite(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<RedeemInviteInput>,
) -> Result<Response, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let did = claims.did().to_string();

    let token_hash = hex::encode(Sha256::digest(input.token.as_bytes()));
    let invite = db::get_invite_by_token_hash(&state.db, state.db_backend, &token_hash)
        .await?
        .ok_or_else(|| AppError::NotFound("Invalid invite token".into()))?;

    if invite.revoked {
        return Err(AppError::BadRequest("This invite has been revoked".into()));
    }

    if let Some(max) = invite.max_uses
        && invite.uses >= max
    {
        return Err(AppError::BadRequest(
            "This invite has reached its maximum uses".into(),
        ));
    }

    if let Some(ref expires) = invite.expires_at {
        let now = now_rfc3339();
        if now > *expires {
            return Err(AppError::BadRequest("This invite has expired".into()));
        }
    }

    let existing = db::get_member(&state.db, state.db_backend, &invite.space_id, &did).await?;
    if existing.is_some() {
        return Err(AppError::Conflict(
            "You are already a member of this space".into(),
        ));
    }

    let member = SpaceMember {
        id: Uuid::new_v4().to_string(),
        space_id: invite.space_id.clone(),
        member_did: did,
        access: invite.access,
        is_delegation: false,
        granted_by: Some(invite.created_by.clone()),
        created_at: now_rfc3339(),
    };

    db::add_member(&state.db, state.db_backend, &member).await?;
    db::increment_invite_uses(&state.db, state.db_backend, &invite.id).await?;

    let space = db::get_space(&state.db, state.db_backend, &invite.space_id).await?;
    let space_uri = space.map(|s| format!("ats://{}/{}/{}", s.owner_did, s.type_nsid, s.skey));

    let mut response = Json(serde_json::json!({
        "spaceUri": space_uri,
        "access": member.access,
    }))
    .into_response();
    *response.status_mut() = StatusCode::CREATED;
    Ok(response)
}

async fn revoke_invite(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<RevokeInviteInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let space = resolve_space(&state, &input.space_uri).await?;
    require_space_admin(&state, &space, claims.did()).await?;

    let revoked = db::revoke_invite(&state.db, state.db_backend, &input.invite_id).await?;
    if !revoked {
        return Err(AppError::NotFound("Invite not found".into()));
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

async fn list_invites(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Query(query): Query<SpaceUriQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let space = resolve_space(&state, &query.space_uri).await?;
    require_space_admin(&state, &space, claims.did()).await?;

    let invites = db::list_invites(&state.db, state.db_backend, &space.id).await?;

    let invites_json: Vec<serde_json::Value> = invites
        .into_iter()
        .map(|i| {
            serde_json::json!({
                "id": i.id,
                "access": i.access,
                "maxUses": i.max_uses,
                "uses": i.uses,
                "expiresAt": i.expires_at,
                "revoked": i.revoked,
                "createdBy": i.created_by,
                "createdAt": i.created_at,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "invites": invites_json })))
}

// ---------------------------------------------------------------------------
// Credential handlers
// ---------------------------------------------------------------------------

async fn get_credential(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<GetCredentialInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let did = claims.did().to_string();
    let space = resolve_space(&state, &input.space_uri).await?;

    require_membership(&state, &space, &did, false, None).await?;

    let encryption_key = state.config.token_encryption_key.as_ref().ok_or_else(|| {
        AppError::Internal("TOKEN_ENCRYPTION_KEY is required for space credentials".into())
    })?;

    let client_id = claims.client_key().map(|k| k.to_string());
    let issued = crate::spaces::auth::issue_credential(
        &state.db,
        state.db_backend,
        encryption_key,
        &space,
        &did,
        client_id.as_deref(),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "credential": issued.token,
        "expiresAt": issued.expires_at,
    })))
}

async fn refresh_credential(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<RefreshCredentialInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let _claims = require_auth(&xrpc_claims)?;
    let space = resolve_space(&state, &input.space_uri).await?;

    let encryption_key = state.config.token_encryption_key.as_ref().ok_or_else(|| {
        AppError::Internal("TOKEN_ENCRYPTION_KEY is required for space credentials".into())
    })?;

    let issued = crate::spaces::auth::refresh_credential(
        &state.db,
        state.db_backend,
        encryption_key,
        &space,
        &input.credential,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "credential": issued.token,
        "expiresAt": issued.expires_at,
    })))
}

// ---------------------------------------------------------------------------
// Notification handlers
// ---------------------------------------------------------------------------

async fn write_notification(
    State(state): State<AppState>,
    xrpc_claims: XrpcClaims,
    Json(input): Json<WriteNotificationInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let claims = require_auth(&xrpc_claims)?;
    let space = resolve_space(&state, &input.space_uri).await?;
    require_space_admin(&state, &space, claims.did()).await?;

    let notification = crate::spaces::notifications::WriteNotification {
        space_uri: input.space_uri,
        author_did: input.author_did,
        collection: input.collection,
        rkey: input.rkey,
        action: input.action,
    };

    crate::spaces::notifications::handle_write_notification(
        &state.db,
        state.db_backend,
        &space.id,
        &notification,
    )
    .await?;

    Ok(Json(serde_json::json!({ "success": true })))
}
