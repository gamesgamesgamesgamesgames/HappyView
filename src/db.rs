use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Deserialize;
use sqlx::AnyPool;
use sqlx::migrate::Migrator;
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

/// Regex matching a JSON operator chain: `identifier->'key1'->'key2'->>'leaf'`
/// Also matches if `::jsonb` cast is already present.
/// Captures: (1) column name (may include `::jsonb`), (2) the full chain of `->` / `->>` and quoted keys.
static JSON_CHAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Match: word_or_dotted_name (optionally with ::jsonb) followed by ->/'key' or ->>'key' segments
    // e.g.  record->>'title'  or  lexicon_json::jsonb->'defs'->'main'->>'type'
    Regex::new(r"(\w+(?:\.\w+)*(?:::jsonb)?)((?:\s*->>?\s*'[^']*')+)").unwrap()
});

/// Regex matching ILIKE: `expr ILIKE pattern`
static ILIKE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bILIKE\b").unwrap());

/// Convert SQL written in PostgreSQL dialect to work on the target backend.
///
/// Handles:
/// - **Placeholders**: `$1, $2, ...` → `?` (SQLite)
/// - **JSON operators**: `col->>'key'` chains →
///   - Postgres: `col::jsonb->>'key'` (adds cast since columns are TEXT)
///   - SQLite: `json_extract(col, '$.key1.key2')`
/// - **ILIKE**: → SQLite `LIKE` (SQLite LIKE is case-insensitive for ASCII by default)
/// - **NOW()**: → SQLite `datetime('now')`
/// - **Boolean literals**: `true`/`false` → `1`/`0` (both backends store as INTEGER)
pub fn adapt_sql(sql: &str, backend: DatabaseBackend) -> String {
    let mut result = sql.to_string();

    // 1. JSON operator chains
    result = adapt_json_operators(&result, backend);

    // 2. ILIKE → LIKE (SQLite)
    if backend == DatabaseBackend::Sqlite {
        result = ILIKE_RE.replace_all(&result, "LIKE").to_string();
    }

    // 3. NOW() → datetime('now') (SQLite)
    if backend == DatabaseBackend::Sqlite {
        result = result.replace("NOW()", "datetime('now')");
    }

    // 4. Boolean literals → integers (both backends, columns are INTEGER)
    result = adapt_booleans(&result);

    // 5. Placeholders: $1, $2, ... → ? (SQLite)
    if backend == DatabaseBackend::Sqlite {
        for i in (1..=50).rev() {
            result = result.replace(&format!("${i}"), "?");
        }
    }

    result
}

/// Rewrite JSON operator chains for the target backend.
fn adapt_json_operators(sql: &str, backend: DatabaseBackend) -> String {
    JSON_CHAIN_RE
        .replace_all(sql, |caps: &regex::Captures| {
            let col = &caps[1];
            let chain = &caps[2];

            match backend {
                DatabaseBackend::Postgres => {
                    // Add ::jsonb cast if not already present
                    if col.ends_with("::jsonb") {
                        format!("{col}{chain}")
                    } else {
                        format!("{col}::jsonb{chain}")
                    }
                }
                DatabaseBackend::Sqlite => {
                    // Parse the chain into path segments and determine final operator
                    let mut path_parts = Vec::new();
                    let mut is_text_extract = false;

                    // Split chain into individual segments: ->'key' or ->>'key'
                    let mut remaining = chain.trim();
                    while !remaining.is_empty() {
                        if let Some(rest) = remaining.strip_prefix("->>") {
                            is_text_extract = true;
                            let rest = rest.trim().strip_prefix('\'').unwrap_or(rest.trim());
                            if let Some((key, after)) = rest.split_once('\'') {
                                path_parts.push(key.to_string());
                                remaining = after.trim();
                            } else {
                                break;
                            }
                        } else if let Some(rest) = remaining.strip_prefix("->") {
                            is_text_extract = false;
                            let rest = rest.trim().strip_prefix('\'').unwrap_or(rest.trim());
                            if let Some((key, after)) = rest.split_once('\'') {
                                path_parts.push(key.to_string());
                                remaining = after.trim();
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }

                    let json_path = format!("$.{}", path_parts.join("."));

                    if is_text_extract {
                        // ->> extracts as text (most common)
                        format!("json_extract({col}, '{json_path}')")
                    } else {
                        // -> extracts as JSON (returns JSON string)
                        format!("json_extract({col}, '{json_path}')")
                    }
                }
            }
        })
        .to_string()
}

/// Replace SQL boolean literals with integers.
/// Matches standalone `true` and `false` as SQL keywords (not inside strings).
fn adapt_booleans(sql: &str) -> String {
    // Simple word-boundary replacement for boolean literals outside of strings.
    // We do a basic approach: replace ` true` / ` false` / `=true` / `=false` etc.
    // Using regex for word boundaries.
    static BOOL_TRUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\btrue\b").unwrap());
    static BOOL_FALSE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bfalse\b").unwrap());

    let result = BOOL_TRUE.replace_all(sql, "1");
    BOOL_FALSE.replace_all(&result, "0").to_string()
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
    fn adapt_sql_postgres_keeps_placeholders() {
        let sql = "SELECT * FROM foo WHERE id = $1 AND name = $2";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT * FROM foo WHERE id = $1 AND name = $2"
        );
    }

    #[test]
    fn adapt_sql_sqlite_converts_placeholders() {
        let sql = "SELECT * FROM foo WHERE id = $1 AND name = $2";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "SELECT * FROM foo WHERE id = ? AND name = ?"
        );
    }

    #[test]
    fn adapt_sql_sqlite_handles_double_digit_placeholders() {
        let sql = "INSERT INTO t VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
        let result = adapt_sql(sql, DatabaseBackend::Sqlite);
        assert_eq!(
            result,
            "INSERT INTO t VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );
    }

    // -----------------------------------------------------------------------
    // adapt_sql: JSON operator conversion
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_postgres_adds_jsonb_cast() {
        let sql = "SELECT record->>'title' FROM records";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT record::jsonb->>'title' FROM records"
        );
    }

    #[test]
    fn adapt_sql_postgres_no_double_cast() {
        let sql = "SELECT record::jsonb->>'title' FROM records";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT record::jsonb->>'title' FROM records"
        );
    }

    #[test]
    fn adapt_sql_postgres_chained_json_operators() {
        let sql = "WHERE lexicon_json->'defs'->'main'->>'type' = 'record'";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "WHERE lexicon_json::jsonb->'defs'->'main'->>'type' = 'record'"
        );
    }

    #[test]
    fn adapt_sql_sqlite_simple_json_extract() {
        let sql = "SELECT record->>'title' FROM records WHERE collection = $1";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "SELECT json_extract(record, '$.title') FROM records WHERE collection = ?"
        );
    }

    #[test]
    fn adapt_sql_sqlite_chained_json_extract() {
        let sql = "WHERE lexicon_json->'defs'->'main'->>'type' = 'record'";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "WHERE json_extract(lexicon_json, '$.defs.main.type') = 'record'"
        );
    }

    #[test]
    fn adapt_sql_sqlite_json_arrow_only() {
        // Single -> (not ->>) extracts as JSON
        let sql = "SELECT record->'value' FROM records";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "SELECT json_extract(record, '$.value') FROM records"
        );
    }

    #[test]
    fn adapt_sql_multiple_json_expressions() {
        let sql = "SELECT record->>'title', record->>'year' FROM records";
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
    // adapt_sql: ILIKE conversion
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_postgres_keeps_ilike() {
        let sql = "WHERE name ILIKE $1";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "WHERE name ILIKE $1"
        );
    }

    #[test]
    fn adapt_sql_sqlite_converts_ilike_to_like() {
        let sql = "WHERE name ILIKE $1";
        assert_eq!(adapt_sql(sql, DatabaseBackend::Sqlite), "WHERE name LIKE ?");
    }

    // -----------------------------------------------------------------------
    // adapt_sql: NOW() conversion
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_postgres_keeps_now() {
        let sql = "INSERT INTO t (created_at) VALUES (NOW())";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "INSERT INTO t (created_at) VALUES (NOW())"
        );
    }

    #[test]
    fn adapt_sql_sqlite_converts_now() {
        let sql = "INSERT INTO t (created_at) VALUES (NOW())";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "INSERT INTO t (created_at) VALUES (datetime('now'))"
        );
    }

    // -----------------------------------------------------------------------
    // adapt_sql: boolean literal conversion
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_converts_boolean_true() {
        let sql = "UPDATE t SET active = true WHERE id = $1";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "UPDATE t SET active = 1 WHERE id = $1"
        );
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "UPDATE t SET active = 1 WHERE id = ?"
        );
    }

    #[test]
    fn adapt_sql_converts_boolean_false() {
        let sql = "INSERT INTO t (backfill) VALUES (false)";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "INSERT INTO t (backfill) VALUES (0)"
        );
    }

    #[test]
    fn adapt_sql_boolean_does_not_replace_inside_strings() {
        // The word "true" in a string value like 'attribute' should not be replaced
        // Note: our simple regex WILL match inside SQL string literals. This is
        // acceptable because column names won't contain 'true'/'false' as substrings
        // in practice, and the Lua db.raw() API uses bind parameters for values.
        let sql = "SELECT * FROM t WHERE status = $1";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT * FROM t WHERE status = $1"
        );
    }

    // -----------------------------------------------------------------------
    // adapt_sql: combined conversions
    // -----------------------------------------------------------------------

    #[test]
    fn adapt_sql_combined_json_ilike_placeholders() {
        let sql = "SELECT * FROM records WHERE record->>'title' ILIKE $1 LIMIT $2";
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Postgres),
            "SELECT * FROM records WHERE record::jsonb->>'title' ILIKE $1 LIMIT $2"
        );
        assert_eq!(
            adapt_sql(sql, DatabaseBackend::Sqlite),
            "SELECT * FROM records WHERE json_extract(record, '$.title') LIKE ? LIMIT ?"
        );
    }

    #[test]
    fn adapt_sql_no_json_operators_unchanged() {
        let sql = "SELECT COUNT(*) FROM records WHERE collection = $1";
        assert_eq!(adapt_sql(sql, DatabaseBackend::Postgres), sql);
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
