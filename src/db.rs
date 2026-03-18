use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::AnyPool;
use sqlx::migrate::Migrator;
use std::path::Path;

/// Database backend type, auto-detected from DATABASE_URL or set via DATABASE_BACKEND.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseBackend {
    Sqlite,
    Postgres,
}

impl DatabaseBackend {
    /// Detect backend from DATABASE_URL prefix.
    pub fn from_url(url: &str) -> Self {
        if url.starts_with("sqlite://") || url.starts_with("sqlite:") {
            DatabaseBackend::Sqlite
        } else {
            DatabaseBackend::Postgres
        }
    }

    /// Parse from string (e.g., from DATABASE_BACKEND env var).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sqlite" => Some(DatabaseBackend::Sqlite),
            "postgres" | "postgresql" => Some(DatabaseBackend::Postgres),
            _ => None,
        }
    }
}

/// Convert PostgreSQL-style placeholders ($1, $2, ...) to SQLite-style (?, ?, ...).
/// Queries should be written with $N placeholders and converted at runtime.
pub fn adapt_sql(sql: &str, backend: DatabaseBackend) -> String {
    match backend {
        DatabaseBackend::Postgres => sql.to_string(),
        DatabaseBackend::Sqlite => {
            // Replace $1, $2, ... with ?
            let mut result = sql.to_string();
            for i in (1..=50).rev() {
                // Reverse order to handle $10 before $1
                result = result.replace(&format!("${i}"), "?");
            }
            result
        }
    }
}

/// Parse a database timestamp string to DateTime<Utc>.
/// Handles RFC 3339 (our app writes), Postgres timestamptz format, and SQLite datetime() format.
pub fn parse_dt(s: &str) -> DateTime<Utc> {
    // Try RFC 3339 first (most common - what our app writes)
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return dt.with_timezone(&Utc);
    }
    // Try SQLite datetime() format: "2025-03-16 12:34:56"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return naive.and_utc();
    }
    // Try Postgres-style with timezone offset: "2025-03-16 12:34:56.123456+00"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return naive.and_utc();
    }
    // Fallback
    tracing::warn!("Failed to parse datetime string: {s}");
    DateTime::UNIX_EPOCH
}

/// Get current UTC time as RFC 3339 string for database binding.
pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

/// Connect to the configured database and run migrations.
pub async fn connect(url: &str, backend: DatabaseBackend) -> AnyPool {
    sqlx::any::install_default_drivers();

    // For SQLite, ensure the parent directory exists
    if backend == DatabaseBackend::Sqlite
        && let Some(path) = url.strip_prefix("sqlite://")
    {
        let path = path.split('?').next().unwrap_or(path);
        if let Some(parent) = std::path::Path::new(path).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                panic!("Failed to create data directory {}: {e}", parent.display())
            });
        }
    }

    let pool = AnyPool::connect(url)
        .await
        .expect("Failed to connect to database");

    // Enable foreign keys and WAL mode for SQLite
    if backend == DatabaseBackend::Sqlite {
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .expect("Failed to enable foreign keys");

        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&pool)
            .await
            .expect("Failed to enable WAL mode");

        sqlx::query("PRAGMA busy_timeout = 5000")
            .execute(&pool)
            .await
            .expect("Failed to set busy timeout");
    }

    // Run migrations from the appropriate directory
    let migration_dir = match backend {
        DatabaseBackend::Sqlite => "./migrations/sqlite",
        DatabaseBackend::Postgres => "./migrations/postgres",
    };

    let migrator = Migrator::new(Path::new(migration_dir))
        .await
        .unwrap_or_else(|e| panic!("Failed to load migrations from {migration_dir}: {e}"));

    migrator.run(&pool).await.expect("Failed to run migrations");

    pool
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn backend_from_url_detects_sqlite() {
        assert_eq!(
            DatabaseBackend::from_url("sqlite://data/happyview.db"),
            DatabaseBackend::Sqlite
        );
        assert_eq!(
            DatabaseBackend::from_url("sqlite:data/happyview.db?mode=rwc"),
            DatabaseBackend::Sqlite
        );
    }

    #[test]
    fn backend_from_url_detects_postgres() {
        assert_eq!(
            DatabaseBackend::from_url("postgres://localhost/happyview"),
            DatabaseBackend::Postgres
        );
        assert_eq!(
            DatabaseBackend::from_url("postgresql://user:pass@host/db"),
            DatabaseBackend::Postgres
        );
    }

    #[test]
    fn backend_from_str_parses() {
        assert_eq!(
            DatabaseBackend::from_str("sqlite"),
            Some(DatabaseBackend::Sqlite)
        );
        assert_eq!(
            DatabaseBackend::from_str("POSTGRES"),
            Some(DatabaseBackend::Postgres)
        );
        assert_eq!(
            DatabaseBackend::from_str("postgresql"),
            Some(DatabaseBackend::Postgres)
        );
        assert_eq!(DatabaseBackend::from_str("invalid"), None);
    }

    #[test]
    fn adapt_sql_postgres_unchanged() {
        let sql = "SELECT * FROM foo WHERE id = $1 AND name = $2";
        assert_eq!(adapt_sql(sql, DatabaseBackend::Postgres), sql);
    }

    #[test]
    fn adapt_sql_sqlite_converts() {
        let sql = "SELECT * FROM foo WHERE id = $1 AND name = $2";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "SELECT * FROM foo WHERE id = ? AND name = ?"
        );
    }

    #[test]
    fn parse_dt_rfc3339() {
        let dt = parse_dt("2025-03-16T12:34:56Z");
        assert_eq!(dt.year(), 2025);
        assert_eq!(dt.month(), 3);
    }

    #[test]
    fn parse_dt_sqlite_format() {
        let dt = parse_dt("2025-03-16 12:34:56");
        assert_eq!(dt.year(), 2025);
        assert_eq!(dt.month(), 3);
    }
}
