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
    pub fn parse(
        raw: Value,
        revision: i32,
        target_collection: Option<String>,
    ) -> Result<Self, String> {
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

impl Default for LexiconRegistry {
    fn default() -> Self {
        Self::new()
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // ParsedLexicon::parse
    // -----------------------------------------------------------------------

    fn record_lexicon_json() -> Value {
        json!({
            "lexicon": 1,
            "id": "games.gamesgamesgamesgames.game",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "properties": {
                            "title": { "type": "string" }
                        }
                    }
                }
            }
        })
    }

    fn query_lexicon_json() -> Value {
        json!({
            "lexicon": 1,
            "id": "games.gamesgamesgamesgames.listGames",
            "defs": {
                "main": {
                    "type": "query",
                    "parameters": {
                        "type": "params",
                        "properties": {
                            "limit": { "type": "integer" }
                        }
                    },
                    "output": {
                        "encoding": "application/json"
                    }
                }
            }
        })
    }

    fn procedure_lexicon_json() -> Value {
        json!({
            "lexicon": 1,
            "id": "games.gamesgamesgamesgames.createGame",
            "defs": {
                "main": {
                    "type": "procedure",
                    "input": {
                        "encoding": "application/json"
                    },
                    "output": {
                        "encoding": "application/json"
                    }
                }
            }
        })
    }

    fn definitions_lexicon_json() -> Value {
        json!({
            "lexicon": 1,
            "id": "games.gamesgamesgamesgames.defs",
            "defs": {
                "genre": {
                    "type": "string",
                    "knownValues": ["action", "rpg"]
                }
            }
        })
    }

    #[test]
    fn parse_record_lexicon() {
        let parsed = ParsedLexicon::parse(record_lexicon_json(), 1, None).unwrap();
        assert_eq!(parsed.id, "games.gamesgamesgamesgames.game");
        assert_eq!(parsed.lexicon_type, LexiconType::Record);
        assert_eq!(parsed.record_key, Some("tid".into()));
        assert!(parsed.record_schema.is_some());
        assert!(parsed.parameters.is_none());
        assert!(parsed.input.is_none());
    }

    #[test]
    fn parse_query_lexicon() {
        let parsed = ParsedLexicon::parse(
            query_lexicon_json(),
            2,
            Some("games.gamesgamesgamesgames.game".into()),
        )
        .unwrap();
        assert_eq!(parsed.lexicon_type, LexiconType::Query);
        assert!(parsed.parameters.is_some());
        assert!(parsed.output.is_some());
        assert_eq!(
            parsed.target_collection,
            Some("games.gamesgamesgamesgames.game".into())
        );
        assert_eq!(parsed.revision, 2);
    }

    #[test]
    fn parse_procedure_lexicon() {
        let parsed = ParsedLexicon::parse(procedure_lexicon_json(), 1, None).unwrap();
        assert_eq!(parsed.lexicon_type, LexiconType::Procedure);
        assert!(parsed.input.is_some());
        assert!(parsed.output.is_some());
    }

    #[test]
    fn parse_definitions_lexicon() {
        let parsed = ParsedLexicon::parse(definitions_lexicon_json(), 1, None).unwrap();
        assert_eq!(parsed.lexicon_type, LexiconType::Definitions);
    }

    #[test]
    fn parse_missing_id_returns_error() {
        let raw = json!({"lexicon": 1, "defs": {}});
        let result = ParsedLexicon::parse(raw, 1, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("id"));
    }

    #[test]
    fn parse_preserves_raw_json() {
        let raw = record_lexicon_json();
        let parsed = ParsedLexicon::parse(raw.clone(), 1, None).unwrap();
        assert_eq!(parsed.raw, raw);
    }

    #[test]
    fn parse_target_collection_passthrough() {
        let parsed =
            ParsedLexicon::parse(query_lexicon_json(), 1, Some("custom.collection".into()))
                .unwrap();
        assert_eq!(parsed.target_collection, Some("custom.collection".into()));
    }

    // -----------------------------------------------------------------------
    // LexiconRegistry
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn registry_new_is_empty() {
        let reg = LexiconRegistry::new();
        assert_eq!(reg.count().await, 0);
    }

    #[tokio::test]
    async fn registry_upsert_and_get() {
        let reg = LexiconRegistry::new();
        let parsed = ParsedLexicon::parse(record_lexicon_json(), 1, None).unwrap();
        reg.upsert(parsed).await;

        let got = reg.get("games.gamesgamesgamesgames.game").await;
        assert!(got.is_some());
        assert_eq!(got.unwrap().lexicon_type, LexiconType::Record);
    }

    #[tokio::test]
    async fn registry_upsert_replaces() {
        let reg = LexiconRegistry::new();
        let v1 = ParsedLexicon::parse(record_lexicon_json(), 1, None).unwrap();
        reg.upsert(v1).await;

        let v2 = ParsedLexicon::parse(record_lexicon_json(), 5, None).unwrap();
        reg.upsert(v2).await;

        assert_eq!(reg.count().await, 1);
        assert_eq!(
            reg.get("games.gamesgamesgamesgames.game")
                .await
                .unwrap()
                .revision,
            5
        );
    }

    #[tokio::test]
    async fn registry_remove_existing() {
        let reg = LexiconRegistry::new();
        let parsed = ParsedLexicon::parse(record_lexicon_json(), 1, None).unwrap();
        reg.upsert(parsed).await;

        assert!(reg.remove("games.gamesgamesgamesgames.game").await);
        assert_eq!(reg.count().await, 0);
    }

    #[tokio::test]
    async fn registry_remove_nonexistent() {
        let reg = LexiconRegistry::new();
        assert!(!reg.remove("nonexistent").await);
    }

    #[tokio::test]
    async fn registry_get_nonexistent() {
        let reg = LexiconRegistry::new();
        assert!(reg.get("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn registry_type_filtered_collections() {
        let reg = LexiconRegistry::new();

        let record = ParsedLexicon::parse(record_lexicon_json(), 1, None).unwrap();
        let query = ParsedLexicon::parse(query_lexicon_json(), 1, None).unwrap();
        let procedure = ParsedLexicon::parse(procedure_lexicon_json(), 1, None).unwrap();
        let defs = ParsedLexicon::parse(definitions_lexicon_json(), 1, None).unwrap();

        reg.upsert(record).await;
        reg.upsert(query).await;
        reg.upsert(procedure).await;
        reg.upsert(defs).await;

        assert_eq!(reg.count().await, 4);

        let records = reg.get_record_collections().await;
        assert_eq!(records.len(), 1);
        assert!(records.contains(&"games.gamesgamesgamesgames.game".to_string()));

        let queries = reg.get_queries().await;
        assert_eq!(queries.len(), 1);
        assert!(queries.contains(&"games.gamesgamesgamesgames.listGames".to_string()));

        let procedures = reg.get_procedures().await;
        assert_eq!(procedures.len(), 1);
        assert!(procedures.contains(&"games.gamesgamesgamesgames.createGame".to_string()));
    }
}
