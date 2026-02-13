use serde_json::{Value, json};

/// A minimal record-type lexicon JSON for testing.
pub fn game_record_lexicon() -> Value {
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

/// A query-type lexicon JSON that targets the game record collection.
pub fn list_games_query_lexicon() -> Value {
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

/// A procedure-type lexicon JSON that targets the game record collection.
pub fn create_game_procedure_lexicon() -> Value {
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

/// A fake DID document for testing PLC directory resolution.
pub fn did_document(did: &str, pds_endpoint: &str) -> Value {
    json!({
        "id": did,
        "alsoKnownAs": [format!("at://test.handle")],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": pds_endpoint
        }]
    })
}

/// A fake app.bsky.actor.profile getRecord response.
pub fn profile_record() -> Value {
    json!({
        "uri": "at://did:plc:test/app.bsky.actor.profile/self",
        "cid": "bafytest",
        "value": {
            "displayName": "Test User",
            "description": "A test user"
        }
    })
}

/// A fake AIP userinfo response.
pub fn userinfo_response(did: &str) -> Value {
    json!({ "sub": did })
}
