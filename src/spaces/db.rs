use crate::db::{DatabaseBackend, adapt_sql, now_rfc3339};
use crate::error::AppError;
use crate::spaces::types::*;

// ---------------------------------------------------------------------------
// Spaces
// ---------------------------------------------------------------------------

pub async fn create_space(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    space: &Space,
) -> Result<(), AppError> {
    let now = now_rfc3339();
    let config_json = serde_json::to_string(&space.config)
        .map_err(|e| AppError::Internal(format!("failed to serialize space config: {e}")))?;
    let allowlist_json = space
        .app_allowlist
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());
    let denylist_json = space
        .app_denylist
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    let sql = adapt_sql(
        "INSERT INTO spaces (id, owner_did, type_nsid, skey, display_name, description, access_mode, app_allowlist, app_denylist, managing_app_did, config, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        backend,
    );

    sqlx::query(&sql)
        .bind(&space.id)
        .bind(&space.owner_did)
        .bind(&space.type_nsid)
        .bind(&space.skey)
        .bind(&space.display_name)
        .bind(&space.description)
        .bind(space.access_mode.as_str())
        .bind(&allowlist_json)
        .bind(&denylist_json)
        .bind(&space.managing_app_did)
        .bind(&config_json)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to create space: {e}")))?;

    Ok(())
}

pub async fn get_space(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    id: &str,
) -> Result<Option<Space>, AppError> {
    let sql = adapt_sql(
        "SELECT id, owner_did, type_nsid, skey, display_name, description, access_mode, app_allowlist, app_denylist, managing_app_did, config, created_at, updated_at FROM spaces WHERE id = ?",
        backend,
    );

    let row: Option<SpaceRow> = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to get space: {e}")))?;

    row.map(parse_space_row).transpose()
}

pub async fn get_space_by_address(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    owner_did: &str,
    type_nsid: &str,
    skey: &str,
) -> Result<Option<Space>, AppError> {
    let sql = adapt_sql(
        "SELECT id, owner_did, type_nsid, skey, display_name, description, access_mode, app_allowlist, app_denylist, managing_app_did, config, created_at, updated_at FROM spaces WHERE owner_did = ? AND type_nsid = ? AND skey = ?",
        backend,
    );

    let row: Option<SpaceRow> = sqlx::query_as(&sql)
        .bind(owner_did)
        .bind(type_nsid)
        .bind(skey)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to get space: {e}")))?;

    row.map(parse_space_row).transpose()
}

pub async fn list_spaces_by_owner(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    owner_did: &str,
) -> Result<Vec<Space>, AppError> {
    let sql = adapt_sql(
        "SELECT id, owner_did, type_nsid, skey, display_name, description, access_mode, app_allowlist, app_denylist, managing_app_did, config, created_at, updated_at FROM spaces WHERE owner_did = ? ORDER BY created_at DESC",
        backend,
    );

    let rows: Vec<SpaceRow> = sqlx::query_as(&sql)
        .bind(owner_did)
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to list spaces: {e}")))?;

    rows.into_iter().map(parse_space_row).collect()
}

pub async fn update_space(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    space: &Space,
) -> Result<bool, AppError> {
    let now = now_rfc3339();
    let config_json = serde_json::to_string(&space.config)
        .map_err(|e| AppError::Internal(format!("failed to serialize space config: {e}")))?;
    let allowlist_json = space
        .app_allowlist
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());
    let denylist_json = space
        .app_denylist
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());

    let sql = adapt_sql(
        "UPDATE spaces SET display_name = ?, description = ?, access_mode = ?, app_allowlist = ?, app_denylist = ?, managing_app_did = ?, config = ?, updated_at = ? WHERE id = ?",
        backend,
    );

    let result = sqlx::query(&sql)
        .bind(&space.display_name)
        .bind(&space.description)
        .bind(space.access_mode.as_str())
        .bind(&allowlist_json)
        .bind(&denylist_json)
        .bind(&space.managing_app_did)
        .bind(&config_json)
        .bind(&now)
        .bind(&space.id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to update space: {e}")))?;

    Ok(result.rows_affected() > 0)
}

pub async fn delete_space(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    id: &str,
) -> Result<bool, AppError> {
    let sql = adapt_sql("DELETE FROM spaces WHERE id = ?", backend);

    let result = sqlx::query(&sql)
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete space: {e}")))?;

    Ok(result.rows_affected() > 0)
}

type SpaceRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    String,
    String,
);

fn parse_space_row(r: SpaceRow) -> Result<Space, AppError> {
    let access_mode = AccessMode::parse(&r.6)
        .ok_or_else(|| AppError::Internal(format!("invalid access_mode: {}", r.6)))?;
    let app_allowlist: Option<Vec<String>> =
        r.7.as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| AppError::Internal(format!("invalid app_allowlist: {e}")))?;
    let app_denylist: Option<Vec<String>> =
        r.8.as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| AppError::Internal(format!("invalid app_denylist: {e}")))?;
    let config: SpaceConfig = serde_json::from_str(&r.10)
        .map_err(|e| AppError::Internal(format!("invalid space config: {e}")))?;

    Ok(Space {
        id: r.0,
        owner_did: r.1,
        type_nsid: r.2,
        skey: r.3,
        display_name: r.4,
        description: r.5,
        access_mode,
        app_allowlist,
        app_denylist,
        managing_app_did: r.9,
        config,
        created_at: r.11,
        updated_at: r.12,
    })
}

// ---------------------------------------------------------------------------
// Space Members
// ---------------------------------------------------------------------------

pub async fn add_member(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    member: &SpaceMember,
) -> Result<(), AppError> {
    let now = now_rfc3339();
    let sql = adapt_sql(
        "INSERT INTO space_members (id, space_id, member_did, access, is_delegation, granted_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        backend,
    );

    sqlx::query(&sql)
        .bind(&member.id)
        .bind(&member.space_id)
        .bind(&member.member_did)
        .bind(member.access.as_str())
        .bind(member.is_delegation as i32)
        .bind(&member.granted_by)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to add member: {e}")))?;

    Ok(())
}

pub async fn remove_member(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    space_id: &str,
    member_did: &str,
) -> Result<bool, AppError> {
    let sql = adapt_sql(
        "DELETE FROM space_members WHERE space_id = ? AND member_did = ?",
        backend,
    );

    let result = sqlx::query(&sql)
        .bind(space_id)
        .bind(member_did)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to remove member: {e}")))?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_member(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    space_id: &str,
    member_did: &str,
) -> Result<Option<SpaceMember>, AppError> {
    let sql = adapt_sql(
        "SELECT id, space_id, member_did, access, is_delegation, granted_by, created_at FROM space_members WHERE space_id = ? AND member_did = ?",
        backend,
    );

    let row: Option<MemberRow> = sqlx::query_as(&sql)
        .bind(space_id)
        .bind(member_did)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to get member: {e}")))?;

    row.map(parse_member_row).transpose()
}

pub async fn list_direct_members(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    space_id: &str,
) -> Result<Vec<SpaceMember>, AppError> {
    let sql = adapt_sql(
        "SELECT id, space_id, member_did, access, is_delegation, granted_by, created_at FROM space_members WHERE space_id = ? ORDER BY created_at ASC",
        backend,
    );

    let rows: Vec<MemberRow> = sqlx::query_as(&sql)
        .bind(space_id)
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to list members: {e}")))?;

    rows.into_iter().map(parse_member_row).collect()
}

pub async fn list_spaces_for_member(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    member_did: &str,
) -> Result<Vec<SpaceMember>, AppError> {
    let sql = adapt_sql(
        "SELECT id, space_id, member_did, access, is_delegation, granted_by, created_at FROM space_members WHERE member_did = ? ORDER BY created_at ASC",
        backend,
    );

    let rows: Vec<MemberRow> = sqlx::query_as(&sql)
        .bind(member_did)
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to list spaces for member: {e}")))?;

    rows.into_iter().map(parse_member_row).collect()
}

type MemberRow = (String, String, String, String, i32, Option<String>, String);

fn parse_member_row(r: MemberRow) -> Result<SpaceMember, AppError> {
    let access = SpaceAccess::parse(&r.3)
        .ok_or_else(|| AppError::Internal(format!("invalid access: {}", r.3)))?;

    Ok(SpaceMember {
        id: r.0,
        space_id: r.1,
        member_did: r.2,
        access,
        is_delegation: r.4 != 0,
        granted_by: r.5,
        created_at: r.6,
    })
}

// ---------------------------------------------------------------------------
// Space Records
// ---------------------------------------------------------------------------

pub async fn upsert_space_record(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    record: &SpaceRecord,
) -> Result<(), AppError> {
    let now = now_rfc3339();
    let record_json = serde_json::to_string(&record.record)
        .map_err(|e| AppError::Internal(format!("failed to serialize record: {e}")))?;

    let sql = match backend {
        DatabaseBackend::Sqlite => {
            "INSERT OR REPLACE INTO space_records (uri, space_id, author_did, collection, rkey, record, cid, indexed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)".to_string()
        }
        DatabaseBackend::Postgres => adapt_sql(
            "INSERT INTO space_records (uri, space_id, author_did, collection, rkey, record, cid, indexed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (uri) DO UPDATE SET record = EXCLUDED.record, cid = EXCLUDED.cid, indexed_at = EXCLUDED.indexed_at",
            backend,
        ),
    };

    sqlx::query(&sql)
        .bind(&record.uri)
        .bind(&record.space_id)
        .bind(&record.author_did)
        .bind(&record.collection)
        .bind(&record.rkey)
        .bind(&record_json)
        .bind(&record.cid)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to upsert space record: {e}")))?;

    Ok(())
}

pub async fn get_space_record(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    uri: &str,
) -> Result<Option<SpaceRecord>, AppError> {
    let sql = adapt_sql(
        "SELECT uri, space_id, author_did, collection, rkey, record, cid, indexed_at FROM space_records WHERE uri = ?",
        backend,
    );

    let row: Option<RecordRow> = sqlx::query_as(&sql)
        .bind(uri)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to get space record: {e}")))?;

    row.map(parse_record_row).transpose()
}

pub async fn get_space_record_by_parts(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    space_id: &str,
    collection: &str,
    rkey: &str,
) -> Result<Option<SpaceRecord>, AppError> {
    let sql = adapt_sql(
        "SELECT uri, space_id, author_did, collection, rkey, record, cid, indexed_at FROM space_records WHERE space_id = ? AND collection = ? AND rkey = ? LIMIT 1",
        backend,
    );

    let row: Option<RecordRow> = sqlx::query_as(&sql)
        .bind(space_id)
        .bind(collection)
        .bind(rkey)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to get space record: {e}")))?;

    row.map(parse_record_row).transpose()
}

pub async fn list_space_records(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    space_id: &str,
    collection: Option<&str>,
    limit: i64,
    cursor: Option<&str>,
) -> Result<Vec<SpaceRecord>, AppError> {
    let (sql, has_collection, has_cursor) = match (collection, cursor) {
        (Some(_), Some(_)) => (
            adapt_sql(
                "SELECT uri, space_id, author_did, collection, rkey, record, cid, indexed_at FROM space_records WHERE space_id = ? AND collection = ? AND indexed_at > ? ORDER BY indexed_at ASC LIMIT ?",
                backend,
            ),
            true,
            true,
        ),
        (Some(_), None) => (
            adapt_sql(
                "SELECT uri, space_id, author_did, collection, rkey, record, cid, indexed_at FROM space_records WHERE space_id = ? AND collection = ? ORDER BY indexed_at ASC LIMIT ?",
                backend,
            ),
            true,
            false,
        ),
        (None, Some(_)) => (
            adapt_sql(
                "SELECT uri, space_id, author_did, collection, rkey, record, cid, indexed_at FROM space_records WHERE space_id = ? AND indexed_at > ? ORDER BY indexed_at ASC LIMIT ?",
                backend,
            ),
            false,
            true,
        ),
        (None, None) => (
            adapt_sql(
                "SELECT uri, space_id, author_did, collection, rkey, record, cid, indexed_at FROM space_records WHERE space_id = ? ORDER BY indexed_at ASC LIMIT ?",
                backend,
            ),
            false,
            false,
        ),
    };

    let mut query = sqlx::query_as::<_, RecordRow>(&sql).bind(space_id);

    if has_collection {
        query = query.bind(collection.unwrap());
    }
    if has_cursor {
        query = query.bind(cursor.unwrap());
    }
    query = query.bind(limit);

    let rows = query
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to list space records: {e}")))?;

    rows.into_iter().map(parse_record_row).collect()
}

pub async fn delete_space_record(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    uri: &str,
) -> Result<bool, AppError> {
    let sql = adapt_sql("DELETE FROM space_records WHERE uri = ?", backend);

    let result = sqlx::query(&sql)
        .bind(uri)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to delete space record: {e}")))?;

    Ok(result.rows_affected() > 0)
}

type RecordRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

fn parse_record_row(r: RecordRow) -> Result<SpaceRecord, AppError> {
    let record: serde_json::Value = serde_json::from_str(&r.5)
        .map_err(|e| AppError::Internal(format!("invalid record JSON: {e}")))?;

    Ok(SpaceRecord {
        uri: r.0,
        space_id: r.1,
        author_did: r.2,
        collection: r.3,
        rkey: r.4,
        record,
        cid: r.6,
        indexed_at: r.7,
    })
}

// ---------------------------------------------------------------------------
// Space Invites
// ---------------------------------------------------------------------------

pub async fn create_invite(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    invite: &SpaceInvite,
) -> Result<(), AppError> {
    let now = now_rfc3339();
    let sql = adapt_sql(
        "INSERT INTO space_invites (id, space_id, token_hash, created_by, access, max_uses, uses, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        backend,
    );

    sqlx::query(&sql)
        .bind(&invite.id)
        .bind(&invite.space_id)
        .bind(&invite.token_hash)
        .bind(&invite.created_by)
        .bind(invite.access.as_str())
        .bind(invite.max_uses)
        .bind(invite.uses)
        .bind(&invite.expires_at)
        .bind(invite.revoked as i32)
        .bind(&now)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to create invite: {e}")))?;

    Ok(())
}

pub async fn get_invite_by_token_hash(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    token_hash: &str,
) -> Result<Option<SpaceInvite>, AppError> {
    let sql = adapt_sql(
        "SELECT id, space_id, token_hash, created_by, access, max_uses, uses, expires_at, revoked, created_at FROM space_invites WHERE token_hash = ?",
        backend,
    );

    let row: Option<InviteRow> = sqlx::query_as(&sql)
        .bind(token_hash)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to get invite: {e}")))?;

    row.map(parse_invite_row).transpose()
}

pub async fn increment_invite_uses(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    invite_id: &str,
) -> Result<(), AppError> {
    let sql = adapt_sql(
        "UPDATE space_invites SET uses = uses + 1 WHERE id = ?",
        backend,
    );

    sqlx::query(&sql)
        .bind(invite_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to increment invite uses: {e}")))?;

    Ok(())
}

pub async fn revoke_invite(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    invite_id: &str,
) -> Result<bool, AppError> {
    let sql = adapt_sql("UPDATE space_invites SET revoked = 1 WHERE id = ?", backend);

    let result = sqlx::query(&sql)
        .bind(invite_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to revoke invite: {e}")))?;

    Ok(result.rows_affected() > 0)
}

pub async fn list_invites(
    pool: &sqlx::AnyPool,
    backend: DatabaseBackend,
    space_id: &str,
) -> Result<Vec<SpaceInvite>, AppError> {
    let sql = adapt_sql(
        "SELECT id, space_id, token_hash, created_by, access, max_uses, uses, expires_at, revoked, created_at FROM space_invites WHERE space_id = ? ORDER BY created_at DESC",
        backend,
    );

    let rows: Vec<InviteRow> = sqlx::query_as(&sql)
        .bind(space_id)
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("failed to list invites: {e}")))?;

    rows.into_iter().map(parse_invite_row).collect()
}

type InviteRow = (
    String,
    String,
    String,
    String,
    String,
    Option<i64>,
    i64,
    Option<String>,
    i32,
    String,
);

fn parse_invite_row(r: InviteRow) -> Result<SpaceInvite, AppError> {
    let access = SpaceAccess::parse(&r.4)
        .ok_or_else(|| AppError::Internal(format!("invalid invite access: {}", r.4)))?;

    Ok(SpaceInvite {
        id: r.0,
        space_id: r.1,
        token_hash: r.2,
        created_by: r.3,
        access,
        max_uses: r.5,
        uses: r.6,
        expires_at: r.7,
        revoked: r.8 != 0,
        created_at: r.9,
    })
}
