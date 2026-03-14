use std::collections::HashSet;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::auth::middleware::Claims;
use crate::error::AppError;
use crate::event_log::{EventLog, Severity, log_event};

use super::permissions::Permission;

pub struct UserAuth {
    pub did: String,
    pub user_id: String,
    pub is_super: bool,
    pub permissions: HashSet<Permission>,
    pub db: sqlx::PgPool,
}

impl UserAuth {
    pub async fn require(&self, permission: Permission) -> Result<(), AppError> {
        if self.is_super || self.permissions.contains(&permission) {
            Ok(())
        } else {
            log_event(
                &self.db,
                EventLog {
                    event_type: "auth.permission_denied".to_string(),
                    severity: Severity::Warn,
                    actor_did: Some(self.did.clone()),
                    subject: Some(permission.as_str().to_string()),
                    detail: serde_json::json!({
                        "user_id": self.user_id,
                        "required_permission": permission.as_str(),
                    }),
                },
            )
            .await;

            Err(AppError::InsufficientPermissions(
                permission.as_str().to_string(),
            ))
        }
    }

    async fn load_permissions(
        db: &sqlx::PgPool,
        user_id: &str,
    ) -> Result<HashSet<Permission>, AppError> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT permission FROM user_permissions WHERE user_id = $1::uuid")
                .bind(user_id)
                .fetch_all(db)
                .await
                .map_err(|e| AppError::Internal(format!("permission query failed: {e}")))?;

        let mut perms = HashSet::new();
        for (perm_str,) in rows {
            if let Ok(p) = serde_json::from_value::<Permission>(serde_json::Value::String(perm_str))
            {
                perms.insert(p);
            }
        }
        Ok(perms)
    }

    async fn load_api_key_permissions(
        db: &sqlx::PgPool,
        user_id: &str,
        key_permissions: &[String],
    ) -> Result<HashSet<Permission>, AppError> {
        let user_perms = Self::load_permissions(db, user_id).await?;
        let mut effective = HashSet::new();
        for perm_str in key_permissions {
            #[allow(clippy::collapsible_if)]
            if let Ok(p) =
                serde_json::from_value::<Permission>(serde_json::Value::String(perm_str.clone()))
            {
                if user_perms.contains(&p) {
                    effective.insert(p);
                }
            }
        }
        Ok(effective)
    }
}

impl FromRequestParts<AppState> for UserAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(auth) = Self::try_api_key_auth(parts, state).await? {
            return Ok(auth);
        }

        let claims = Claims::from_request_parts(parts, state).await?;
        let did = claims.did().to_string();

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Internal(format!("user count query failed: {e}")))?;

        if count.0 == 0 {
            let mut tx = state
                .db
                .begin()
                .await
                .map_err(|e| AppError::Internal(format!("transaction start failed: {e}")))?;

            sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                .execute(&mut *tx)
                .await
                .map_err(|e| AppError::Internal(format!("set isolation failed: {e}")))?;

            let row: Option<(String,)> = sqlx::query_as(
                "INSERT INTO users (did, is_super) VALUES ($1, TRUE)
                 ON CONFLICT (did) DO NOTHING
                 RETURNING id::text",
            )
            .bind(&did)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("auto-bootstrap user failed: {e}")))?;

            if let Some((user_id,)) = row {
                for perm in Permission::all() {
                    sqlx::query(
                        "INSERT INTO user_permissions (user_id, permission)
                         VALUES ($1::uuid, $2)
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(&user_id)
                    .bind(perm.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        AppError::Internal(format!("bootstrap permissions failed: {e}"))
                    })?;
                }

                tx.commit()
                    .await
                    .map_err(|e| AppError::Internal(format!("transaction commit failed: {e}")))?;

                tracing::info!(did = %did, "auto-bootstrapped first super user");

                log_event(
                    &state.db,
                    EventLog {
                        event_type: "user.bootstrapped".to_string(),
                        severity: Severity::Info,
                        actor_did: None,
                        subject: Some(did.clone()),
                        detail: serde_json::json!({}),
                    },
                )
                .await;
            } else {
                tx.commit()
                    .await
                    .map_err(|e| AppError::Internal(format!("transaction commit failed: {e}")))?;
            }
        }

        let found: Option<(String, bool)> =
            sqlx::query_as("SELECT id::text, is_super FROM users WHERE did = $1")
                .bind(&did)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| AppError::Internal(format!("user auth query failed: {e}")))?;

        let Some((user_id, is_super)) = found else {
            return Err(AppError::Forbidden("not a user".into()));
        };

        let permissions = if is_super {
            HashSet::new()
        } else {
            Self::load_permissions(&state.db, &user_id).await?
        };

        let db = state.db.clone();
        let uid = user_id.clone();
        tokio::spawn(async move {
            let _ = sqlx::query("UPDATE users SET last_used_at = NOW() WHERE id::text = $1")
                .bind(&uid)
                .execute(&db)
                .await;
        });

        Ok(UserAuth {
            did,
            user_id,
            is_super,
            permissions,
            db: state.db.clone(),
        })
    }
}

impl UserAuth {
    async fn try_api_key_auth(parts: &Parts, state: &AppState) -> Result<Option<Self>, AppError> {
        let header = match parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
        {
            Some(h) => h,
            None => return Ok(None),
        };

        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("DPoP "));

        let token = match token {
            Some(t) if t.starts_with("hv_") => t,
            _ => return Ok(None),
        };

        let hash = hex::encode(Sha256::digest(token.as_bytes()));

        let row: Option<(String, String, String, bool, Vec<String>)> = sqlx::query_as(
            "SELECT k.id::text, u.id::text, u.did, u.is_super, k.permissions
             FROM api_keys k
             JOIN users u ON u.id = k.user_id
             WHERE k.key_hash = $1 AND k.revoked_at IS NULL",
        )
        .bind(&hash)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(format!("api key lookup failed: {e}")))?;

        let Some((key_id, user_id, did, is_super, key_permissions)) = row else {
            return Err(AppError::Auth("invalid or revoked API key".into()));
        };

        let permissions = if is_super {
            HashSet::new()
        } else {
            Self::load_api_key_permissions(&state.db, &user_id, &key_permissions).await?
        };

        let db = state.db.clone();
        tokio::spawn(async move {
            let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id::text = $1")
                .bind(&key_id)
                .execute(&db)
                .await;
        });

        Ok(Some(UserAuth {
            did,
            user_id,
            is_super,
            permissions,
            db: state.db.clone(),
        }))
    }
}
