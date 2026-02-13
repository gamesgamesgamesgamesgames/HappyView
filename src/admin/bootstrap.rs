use super::hash::hash_api_key;

/// Bootstrap: if no admins exist and ADMIN_SECRET is set, create a bootstrap admin.
pub async fn bootstrap(db: &sqlx::PgPool, admin_secret: &Option<String>) {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM admins")
        .fetch_one(db)
        .await
        .unwrap_or((0,));

    if count.0 > 0 {
        return;
    }

    if let Some(secret) = admin_secret {
        let key_hash = hash_api_key(secret);
        let _ = sqlx::query(
            "INSERT INTO admins (name, api_key_hash) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind("bootstrap")
        .bind(&key_hash)
        .execute(db)
        .await;
        tracing::info!("created bootstrap admin from ADMIN_SECRET");
    }
}
