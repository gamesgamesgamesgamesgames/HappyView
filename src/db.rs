use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Deserialize;
use sqlx::AnyPool;
use sqlx::migrate::Migrator;
use sqlx::pool::PoolOptions;
use std::path::Path;
use std::sync::LazyLock;

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

/// Regex matching `json_extract(col, '$.path.to.leaf')`
/// Captures: (1) column name, (2) the JSON path after `$.`
static JSON_EXTRACT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"json_extract\((\w+(?:\.\w+)*),\s*'\$\.([^']+)'\)").unwrap());

/// Regex matching `datetime('now', '±N unit')`
/// Captures: (1) sign (+/-), (2) the interval value e.g. "7 days"
static DATETIME_INTERVAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"datetime\('now',\s*'([+-])(\d+\s+[^']+)'\)").unwrap());

/// Regex matching bare `datetime('now')`
static DATETIME_NOW_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"datetime\('now'\)").unwrap());

/// Convert SQL written in SQLite dialect to work on the target backend.
///
/// Source SQL uses SQLite syntax:
/// - `?` placeholders
/// - `json_extract(col, '$.path')` for JSON access
/// - `datetime('now')` / `datetime('now', '±N unit')` for timestamps
/// - `LIKE` for case-insensitive matching
/// - `0`/`1` for booleans
///
/// For Postgres, converts to:
/// - `$1, $2, $3...` numbered placeholders
/// - `col::jsonb->'seg1'->'seg2'->>'leaf'` JSON chains
/// - `NOW()` / `NOW() ± INTERVAL 'N unit'`
/// - `LIKE` stays as-is (works on both)
/// - `0`/`1` stays as-is (works on both)
pub fn adapt_sql(sql: &str, backend: DatabaseBackend) -> String {
    match backend {
        DatabaseBackend::Sqlite => {
            // Source is already SQLite — no-op
            sql.to_string()
        }
        DatabaseBackend::Postgres => {
            let mut result = sql.to_string();

            // 1. json_extract → Postgres JSON chain
            result = adapt_json_extract_to_postgres(&result);

            // 2. datetime('now', '±N unit') → NOW() ± INTERVAL 'N unit'
            //    Must run before bare datetime('now') replacement.
            result = DATETIME_INTERVAL_RE
                .replace_all(&result, |caps: &regex::Captures| {
                    let sign = &caps[1];
                    let interval = &caps[2];
                    format!("NOW() {sign} INTERVAL '{interval}'")
                })
                .to_string();

            // 3. datetime('now') → NOW()
            result = DATETIME_NOW_RE.replace_all(&result, "NOW()").to_string();

            // 4. ? → $1, $2, $3... (quote-aware)
            result = adapt_placeholders_to_postgres(&result);

            result
        }
    }
}

/// Convert `json_extract(col, '$.seg1.seg2.leaf')` to Postgres `col::jsonb->'seg1'->'seg2'->>'leaf'`.
fn adapt_json_extract_to_postgres(sql: &str) -> String {
    JSON_EXTRACT_RE
        .replace_all(sql, |caps: &regex::Captures| {
            let col = &caps[1];
            let path = &caps[2]; // e.g. "defs.main.type" or "title"

            let segments: Vec<&str> = path.split('.').collect();
            let mut chain = format!("{col}::jsonb");

            for (i, seg) in segments.iter().enumerate() {
                if i == segments.len() - 1 {
                    // Last segment uses ->> (text extraction)
                    chain.push_str(&format!("->>'{seg}'"));
                } else {
                    // Intermediate segments use -> (JSON traversal)
                    chain.push_str(&format!("->'{seg}'"));
                }
            }

            chain
        })
        .to_string()
}

/// Convert `?` placeholders to `$1, $2, $3...` for Postgres, skipping `?` inside single-quoted strings.
fn adapt_placeholders_to_postgres(sql: &str) -> String {
    let mut result = String::with_capacity(sql.len());
    let mut counter = 0u32;
    let mut in_string = false;

    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            if in_string {
                // Check for escaped quote ''
                if i + 1 < chars.len() && chars[i + 1] == '\'' {
                    result.push('\'');
                    result.push('\'');
                    i += 2;
                    continue;
                }
                in_string = false;
            } else {
                in_string = true;
            }
            result.push(c);
        } else if c == '?' && !in_string {
            counter += 1;
            result.push('$');
            result.push_str(&counter.to_string());
        } else {
            result.push(c);
        }
        i += 1;
    }

    result
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

    let max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(match backend {
            DatabaseBackend::Sqlite => 16,
            DatabaseBackend::Postgres => 32,
        });

    let pool = PoolOptions::<sqlx::Any>::new()
        .max_connections(max_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .connect(url)
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

    // -----------------------------------------------------------------------
    // DatabaseBackend detection
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // adapt_sql: placeholder conversion
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_sqlite_keeps_placeholders() {
        let sql = "SELECT * FROM foo WHERE id = ? AND name = ?";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "SELECT * FROM foo WHERE id = ? AND name = ?"
        );
    }

    #[test]
    fn adapt_sql_postgres_converts_placeholders() {
        let sql = "SELECT * FROM foo WHERE id = ? AND name = ?";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT * FROM foo WHERE id = $1 AND name = $2"
        );
    }

    #[test]
    fn adapt_sql_postgres_handles_many_placeholders() {
        let sql = "INSERT INTO t VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        let result = adapt_sql(sql, DatabaseBackend::Postgres);
        assert_eq!(
            result,
            "INSERT INTO t VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
        );
    }

    #[test]
    fn adapt_sql_postgres_skips_question_marks_in_strings() {
        let sql = "SELECT * FROM foo WHERE name = ? AND note LIKE '??%'";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT * FROM foo WHERE name = $1 AND note LIKE '??%'"
        );
    }

    // -----------------------------------------------------------------------
    // adapt_sql: JSON operator conversion
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_sqlite_keeps_json_extract() {
        let sql = "SELECT json_extract(record, '$.title') FROM records";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "SELECT json_extract(record, '$.title') FROM records"
        );
    }

    #[test]
    fn adapt_sql_postgres_converts_simple_json_extract() {
        let sql = "SELECT json_extract(record, '$.title') FROM records WHERE collection = ?";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT record::jsonb->>'title' FROM records WHERE collection = $1"
        );
    }

    #[test]
    fn adapt_sql_postgres_converts_chained_json_extract() {
        let sql = "WHERE json_extract(lexicon_json, '$.defs.main.type') = 'record'";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "WHERE lexicon_json::jsonb->'defs'->'main'->>'type' = 'record'"
        );
    }

    #[test]
    fn adapt_sql_multiple_json_expressions() {
        let sql =
            "SELECT json_extract(record, '$.title'), json_extract(record, '$.year') FROM records";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT record::jsonb->>'title', record::jsonb->>'year' FROM records"
        );
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "SELECT json_extract(record, '$.title'), json_extract(record, '$.year') FROM records"
        );
    }

    // -----------------------------------------------------------------------
    // adapt_sql: LIKE stays as-is
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_postgres_keeps_like() {
        let sql = "WHERE name LIKE ?";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "WHERE name LIKE $1"
        );
    }

    #[test]
    fn adapt_sql_sqlite_keeps_like() {
        let sql = "WHERE name LIKE ?";
        assert_eq!(adapt_sql(sql, DatabaseBackend::Sqlite), "WHERE name LIKE ?");
    }

    // -----------------------------------------------------------------------
    // adapt_sql: datetime('now') conversion
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_sqlite_keeps_datetime_now() {
        let sql = "INSERT INTO t (created_at) VALUES (datetime('now'))";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "INSERT INTO t (created_at) VALUES (datetime('now'))"
        );
    }

    #[test]
    fn adapt_sql_postgres_converts_datetime_now() {
        let sql = "INSERT INTO t (created_at) VALUES (datetime('now'))";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "INSERT INTO t (created_at) VALUES (NOW())"
        );
    }

    // -----------------------------------------------------------------------
    // adapt_sql: datetime('now', '±N unit') conversion
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_sqlite_keeps_datetime_interval() {
        let sql = "WHERE indexed_at > datetime('now', '-7 days')";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "WHERE indexed_at > datetime('now', '-7 days')"
        );
    }

    #[test]
    fn adapt_sql_postgres_converts_datetime_minus_interval() {
        let sql = "WHERE indexed_at > datetime('now', '-7 days')";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "WHERE indexed_at > NOW() - INTERVAL '7 days'"
        );
    }

    #[test]
    fn adapt_sql_postgres_converts_datetime_plus_interval() {
        let sql = "WHERE expires_at < datetime('now', '+30 minutes')";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "WHERE expires_at < NOW() + INTERVAL '30 minutes'"
        );
    }

    #[test]
    fn adapt_sql_postgres_interval_with_json_and_placeholders() {
        let sql = "SELECT json_extract(record, '$.subject') FROM records WHERE collection = ? AND indexed_at > datetime('now', '-7 days') LIMIT ?";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT record::jsonb->>'subject' FROM records WHERE collection = $1 AND indexed_at > NOW() - INTERVAL '7 days' LIMIT $2"
        );
    }

    // -----------------------------------------------------------------------
    // adapt_sql: boolean literals stay as 0/1
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_keeps_integer_booleans() {
        let sql = "UPDATE t SET active = 1 WHERE id = ?";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "UPDATE t SET active = 1 WHERE id = $1"
        );
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "UPDATE t SET active = 1 WHERE id = ?"
        );
    }

    // -----------------------------------------------------------------------
    // adapt_sql: combined conversions
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_combined_json_like_placeholders() {
        let sql = "SELECT * FROM records WHERE json_extract(record, '$.title') LIKE ? LIMIT ?";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT * FROM records WHERE record::jsonb->>'title' LIKE $1 LIMIT $2"
        );
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "SELECT * FROM records WHERE json_extract(record, '$.title') LIKE ? LIMIT ?"
        );
    }

    #[test]
    fn adapt_sql_no_json_operators_unchanged() {
        let sql = "SELECT COUNT(*) FROM records WHERE collection = ?";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT COUNT(*) FROM records WHERE collection = $1"
        );
    }

    // -----------------------------------------------------------------------
    // parse_dt
    // -----------------------------------------------------------------------

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
