use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// The type of a lexicon's `main` definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LexiconType {
    Record,
    Query,
    Procedure,
    /// Lexicons with no `main` def or a non-endpoint main type (token, object, string, etc.).
    Definitions,
}

/// Metadata extracted from a raw lexicon JSON document.
#[derive(Debug, Clone)]
pub struct ParsedLexicon {
    /// The NSID, e.g. "games.gamesgamesgamesgames.game".
    pub id: String,
    /// What kind of endpoint this lexicon defines.
    pub lexicon_type: LexiconType,
    /// For records: the `key` field (e.g. "tid", "any", "literal:self").
    pub record_key: Option<String>,
    /// For queries: the parameters schema from `defs.main.parameters`.
    pub parameters: Option<Value>,
    /// For procedures: the input schema from `defs.main.input`.
    pub input: Option<Value>,
    /// For queries and procedures: the output schema from `defs.main.output`.
    pub output: Option<Value>,
    /// For records: the record schema from `defs.main.record`.
    pub record_schema: Option<Value>,
    /// The entire raw lexicon JSON.
    pub raw: Value,
    /// Database revision number.
    pub revision: i32,
    /// For queries/procedures: the backing record collection NSID.
    pub target_collection: Option<String>,
}

impl ParsedLexicon {
    /// Parse a lexicon JSON document into a `ParsedLexicon`.
    pub fn parse(raw: Value, revision: i32, target_collection: Option<String>) -> Result<Self, String> {
        let id = raw
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("lexicon JSON missing 'id' field")?
            .to_string();

        let main_def = raw.get("defs").and_then(|d| d.get("main"));

        let main_type_str = main_def
            .and_then(|m| m.get("type"))
            .and_then(|t| t.as_str());

        let lexicon_type = match main_type_str {
            Some("record") => LexiconType::Record,
            Some("query") => LexiconType::Query,
            Some("procedure") => LexiconType::Procedure,
            _ => LexiconType::Definitions,
        };

        let record_key = main_def
            .and_then(|m| m.get("key"))
            .and_then(|k| k.as_str())
            .map(|s| s.to_string());

        let parameters = main_def.and_then(|m| m.get("parameters")).cloned();
        let input = main_def.and_then(|m| m.get("input")).cloned();
        let output = main_def.and_then(|m| m.get("output")).cloned();
        let record_schema = main_def.and_then(|m| m.get("record")).cloned();

        Ok(Self {
            id,
            lexicon_type,
            record_key,
            parameters,
            input,
            output,
            record_schema,
            raw,
            revision,
            target_collection,
        })
    }
}

/// In-memory cache of all parsed lexicons, keyed by NSID.
#[derive(Debug, Clone)]
pub struct LexiconRegistry {
    inner: Arc<RwLock<HashMap<String, ParsedLexicon>>>,
}

impl LexiconRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load all lexicons from the database, replacing any existing entries.
    pub async fn load_from_db(&self, db: &sqlx::PgPool) -> Result<(), String> {
        let rows: Vec<(String, Value, i32, Option<String>)> =
            sqlx::query_as("SELECT id, lexicon_json, revision, target_collection FROM lexicons")
                .fetch_all(db)
                .await
                .map_err(|e| format!("failed to load lexicons: {e}"))?;

        let mut inner = self.inner.write().await;
        inner.clear();

        let mut loaded = 0u32;
        for (id, json, revision, target_collection) in rows {
            match ParsedLexicon::parse(json, revision, target_collection) {
                Ok(parsed) => {
                    inner.insert(id, parsed);
                    loaded += 1;
                }
                Err(e) => {
                    warn!(%id, "failed to parse lexicon: {e}");
                }
            }
        }

        info!(count = loaded, "loaded lexicons into registry");
        Ok(())
    }

    /// Insert or update a single lexicon in the registry.
    pub async fn upsert(&self, parsed: ParsedLexicon) {
        let mut inner = self.inner.write().await;
        inner.insert(parsed.id.clone(), parsed);
    }

    /// Remove a lexicon from the registry by NSID.
    pub async fn remove(&self, id: &str) -> bool {
        let mut inner = self.inner.write().await;
        inner.remove(id).is_some()
    }

    /// Get a single lexicon by NSID.
    pub async fn get(&self, id: &str) -> Option<ParsedLexicon> {
        let inner = self.inner.read().await;
        inner.get(id).cloned()
    }

    /// Return NSIDs of all record-type lexicons.
    pub async fn get_record_collections(&self) -> Vec<String> {
        let inner = self.inner.read().await;
        inner
            .values()
            .filter(|lex| lex.lexicon_type == LexiconType::Record)
            .map(|lex| lex.id.clone())
            .collect()
    }

    /// Return NSIDs of all query-type lexicons.
    pub async fn get_queries(&self) -> Vec<String> {
        let inner = self.inner.read().await;
        inner
            .values()
            .filter(|lex| lex.lexicon_type == LexiconType::Query)
            .map(|lex| lex.id.clone())
            .collect()
    }

    /// Return NSIDs of all procedure-type lexicons.
    pub async fn get_procedures(&self) -> Vec<String> {
        let inner = self.inner.read().await;
        inner
            .values()
            .filter(|lex| lex.lexicon_type == LexiconType::Procedure)
            .map(|lex| lex.id.clone())
            .collect()
    }

    /// Return the total count of registered lexicons.
    pub async fn count(&self) -> usize {
        let inner = self.inner.read().await;
        inner.len()
    }
}
