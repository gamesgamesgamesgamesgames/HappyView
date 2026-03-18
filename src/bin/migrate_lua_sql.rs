use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// A single SQL transformation with location info for reporting.
struct SqlChange {
    file: PathBuf,
    line: usize,
    original: String,
    converted: String,
    warnings: Vec<String>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut dir = std::env::current_dir().expect("cannot determine current directory");
    let mut dry_run = false;
    let mut report_only = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => dry_run = true,
            "--report" => report_only = true,
            "--help" | "-h" => {
                eprintln!("Usage: migrate-lua-sql [OPTIONS] [DIRECTORY]");
                eprintln!();
                eprintln!("Converts Postgres SQL in Lua db.raw() calls to SQLite syntax.");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --dry-run   Show what would change without modifying files");
                eprintln!("  --report    Only report changes and warnings (implies --dry-run)");
                eprintln!("  -h, --help  Show this help");
                std::process::exit(0);
            }
            other => {
                dir = PathBuf::from(other);
            }
        }
        i += 1;
    }

    if report_only {
        dry_run = true;
    }

    let lua_files = find_lua_files(&dir);
    if lua_files.is_empty() {
        eprintln!("No .lua files found in {}", dir.display());
        std::process::exit(0);
    }

    let mut total_changes = 0;
    let mut total_warnings = 0;
    let mut files_modified = 0;

    for path in &lua_files {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: cannot read {}: {}", path.display(), e);
                continue;
            }
        };

        let (new_content, changes) = transform_file(path, &content);

        if changes.is_empty() {
            continue;
        }

        files_modified += 1;

        for change in &changes {
            total_changes += 1;
            total_warnings += change.warnings.len();

            if report_only || dry_run {
                println!("--- {}:{}", change.file.display(), change.line);
                println!("  Original:  {}", change.original.trim());
                println!("  Converted: {}", change.converted.trim());
                for w in &change.warnings {
                    println!("  WARNING: {}", w);
                }
                println!();
            }
        }

        if !dry_run && let Err(e) = fs::write(path, &new_content) {
            eprintln!("Error writing {}: {}", path.display(), e);
        }
    }

    let mode = if report_only {
        "Report"
    } else if dry_run {
        "Dry run"
    } else {
        "Applied"
    };

    println!(
        "{}: {} changes across {} files ({} warnings)",
        mode, total_changes, files_modified, total_warnings
    );
}

fn find_lua_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    find_lua_files_recursive(dir, &mut files);
    files.sort();
    files
}

fn find_lua_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            find_lua_files_recursive(&path, files);
        } else if path.extension().and_then(|s| s.to_str()) == Some("lua") {
            files.push(path);
        }
    }
}

/// Check if a string looks like it contains SQL.
/// Requires at least one strong SQL keyword (statement-level), not just connectors.
fn looks_like_sql(s: &str) -> bool {
    let upper = s.to_uppercase();
    let strong_keywords = [
        "SELECT ",
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "FROM ",
        "WHERE ",
        "JOIN ",
        "ORDER BY",
        "GROUP BY",
        "HAVING ",
        "LIMIT ",
        "VALUES",
        "ON CONFLICT",
    ];
    strong_keywords.iter().any(|kw| upper.contains(kw))
}

/// Transform an entire file, returning the new content and a list of changes.
///
/// Scans every quoted string literal on each line. If the string looks like SQL
/// (contains common SQL keywords), it applies Postgres-to-SQLite transformations.
/// This handles both inline db.raw("...") calls and SQL built via variable
/// assignment with `..` concatenation.
fn transform_file(path: &Path, content: &str) -> (String, Vec<SqlChange>) {
    let mut changes = Vec::new();
    let mut result = String::with_capacity(content.len());

    // Match double-quoted and single-quoted string literals
    let sql_string_re = Regex::new(r#"("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"#).unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let mut new_line = line.to_string();
        let mut line_changed = false;

        // Find all string literals on this line
        let matches: Vec<_> = sql_string_re.find_iter(line).collect();

        // Process matches in reverse order so byte offsets remain valid
        for m in matches.into_iter().rev() {
            let full_match = m.as_str();
            let quote_char = full_match.chars().next().unwrap();
            let inner = &full_match[1..full_match.len() - 1];

            // Only process strings that look like SQL
            if !looks_like_sql(inner) {
                continue;
            }

            let (converted, warnings) = convert_sql(inner);

            if converted != inner || !warnings.is_empty() {
                let replacement = format!("{}{}{}", quote_char, converted, quote_char);
                new_line = format!(
                    "{}{}{}",
                    &new_line[..m.start()],
                    replacement,
                    &new_line[m.end()..]
                );
                line_changed = true;

                changes.push(SqlChange {
                    file: path.to_path_buf(),
                    line: line_idx + 1,
                    original: inner.to_string(),
                    converted: converted.clone(),
                    warnings,
                });
            }
        }

        if line_changed {
            result.push_str(&new_line);
        } else {
            result.push_str(line);
        }
        result.push('\n');
    }

    // Preserve trailing newline behavior of original
    if !content.ends_with('\n') && result.ends_with('\n') {
        result.pop();
    }

    (result, changes)
}

/// Convert a single SQL string from Postgres to SQLite syntax.
/// Returns (converted_sql, warnings).
fn convert_sql(sql: &str) -> (String, Vec<String>) {
    let mut result = sql.to_string();
    let mut warnings = Vec::new();

    // Check for unsupported patterns first (before any transformations)
    check_unsupported_patterns(&result, &mut warnings);

    // 1. JSON operators: must be done before $N replacement since -> uses > char
    result = convert_json_operators(&result);

    // 2. $1, $2, ... -> ? (in order)
    result = convert_placeholders(&result);

    // 3. ILIKE -> LIKE (SQLite LIKE is already case-insensitive for ASCII)
    let ilike_re = Regex::new(r"(?i)\bILIKE\b").unwrap();
    result = ilike_re.replace_all(&result, "LIKE").to_string();

    // 4. NOW() +/- INTERVAL '...' -> datetime('now', '...')
    //    Must be done before bare NOW() replacement
    result = convert_now_interval(&result);

    // 5. Bare NOW() -> datetime('now')
    let now_re = Regex::new(r"(?i)\bNOW\(\)").unwrap();
    result = now_re.replace_all(&result, "datetime('now')").to_string();

    // 6. Boolean literals: true -> 1, false -> 0
    let true_re = Regex::new(r"\btrue\b").unwrap();
    let false_re = Regex::new(r"\bfalse\b").unwrap();
    result = true_re.replace_all(&result, "1").to_string();
    result = false_re.replace_all(&result, "0").to_string();

    (result, warnings)
}

/// Convert $1, $2, etc. to ? in order.
fn convert_placeholders(sql: &str) -> String {
    let re = Regex::new(r"\$(\d+)").unwrap();

    // Track which placeholder numbers exist (for potential future validation)
    let mut _seen: HashSet<u32> = HashSet::new();
    for cap in re.captures_iter(sql) {
        let n: u32 = cap[1].parse().unwrap_or(0);
        _seen.insert(n);
    }

    // Replace all $N with ?
    re.replace_all(sql, "?").to_string()
}

/// Convert Postgres JSON operators to json_extract().
///
/// Handles chains like:
///   col->>'key'           => json_extract(col, '$.key')
///   col->'a'->'b'->>'c'   => json_extract(col, '$.a.b.c')
///   col::jsonb->'a'->>'b' => json_extract(col, '$.a.b')
fn convert_json_operators(sql: &str) -> String {
    // Match a chain of -> / ->> operators starting from an identifier
    // The identifier may have an optional ::jsonb cast which we strip
    // Use a non-capturing group for the repetition so we capture the ENTIRE chain
    let chain_re =
        Regex::new(r"(\b[a-zA-Z_][a-zA-Z0-9_.]*)(::jsonb)?((?:\s*->>?\s*'[^']*')+)").unwrap();

    chain_re
        .replace_all(sql, |caps: &regex::Captures| {
            let col = &caps[1];
            // caps[2] is optional ::jsonb cast — we strip it
            let chain_str = &caps[3]; // now captures the full chain

            // Parse each arrow and key from the chain
            let arrow_re = Regex::new(r"(->>?)\s*'([^']*)'").unwrap();
            let mut keys: Vec<String> = Vec::new();

            for arrow_cap in arrow_re.captures_iter(chain_str) {
                keys.push(arrow_cap[2].to_string());
            }

            let json_path = format!("$.{}", keys.join("."));
            format!("json_extract({}, '{}')", col, json_path)
        })
        .to_string()
}

/// Convert NOW() +/- INTERVAL 'X unit' to datetime('now', '+/-X unit').
fn convert_now_interval(sql: &str) -> String {
    let re = Regex::new(r"(?i)\bNOW\(\)\s*([+-])\s*INTERVAL\s*'([^']+)'").unwrap();

    re.replace_all(sql, |caps: &regex::Captures| {
        let sign = &caps[1];
        let interval = &caps[2];
        format!("datetime('now', '{}{}')", sign, interval)
    })
    .to_string()
}

/// Check for patterns that cannot be auto-converted and add warnings.
fn check_unsupported_patterns(sql: &str, warnings: &mut Vec<String>) {
    // JSONB ? operator (contains-key): record->'approvedGames' ? $1
    let jsonb_contains_re = Regex::new(r"'\s+\?\s+\$\d+").unwrap();
    if jsonb_contains_re.is_match(sql) {
        warnings.push(
            "JSONB '?' (contains-key) operator detected -- no direct SQLite equivalent. \
             Consider using json_each() with an EXISTS subquery."
                .to_string(),
        );
    }

    // make_interval()
    if sql.to_lowercase().contains("make_interval") {
        warnings
            .push("make_interval() is Postgres-specific -- needs manual conversion.".to_string());
    }

    // SIMILAR TO
    let similar_re = Regex::new(r"(?i)\bSIMILAR\s+TO\b").unwrap();
    if similar_re.is_match(sql) {
        warnings.push("SIMILAR TO is Postgres-specific -- use LIKE or GLOB instead.".to_string());
    }

    // ANY() / ALL() array operators
    let any_re = Regex::new(r"(?i)\bANY\s*\(").unwrap();
    let all_re = Regex::new(r"(?i)\bALL\s*\(").unwrap();
    if any_re.is_match(sql) {
        warnings.push("ANY() array operator detected -- no direct SQLite equivalent.".to_string());
    }
    if all_re.is_match(sql) {
        warnings.push("ALL() array operator detected -- no direct SQLite equivalent.".to_string());
    }

    // ::type casts other than ::jsonb
    let cast_re = Regex::new(r"::[a-zA-Z_]+").unwrap();
    for m in cast_re.find_iter(sql) {
        let cast = m.as_str();
        if cast != "::jsonb" {
            warnings.push(format!(
                "Type cast '{}' detected -- may need manual conversion.",
                cast
            ));
        }
    }
}
