use std::str::FromStr;
use tracing::{debug, error, info, warn};

/// Log level for plugin logging
#[derive(Debug, Clone, Copy, Default)]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl FromStr for LogLevel {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "debug" => Self::Debug,
            "info" => Self::Info,
            "warn" | "warning" => Self::Warn,
            "error" => Self::Error,
            _ => Self::Info,
        })
    }
}

/// Log a message from a plugin.
///
/// Always emits to `tracing`. If `db` is `Some`, also spawns a detached task
/// that writes the event to the `event_logs` table so it appears in the
/// Event Logs UI. The spawned task is fire-and-forget; errors are logged by
/// `event_log::log_event` but not returned to the caller.
pub fn log(
    plugin_id: &str,
    level: LogLevel,
    message: &str,
    db: Option<sqlx::AnyPool>,
    db_backend: crate::db::DatabaseBackend,
) {
    match level {
        LogLevel::Debug => debug!(plugin = %plugin_id, "{}", message),
        LogLevel::Info => info!(plugin = %plugin_id, "{}", message),
        LogLevel::Warn => warn!(plugin = %plugin_id, "{}", message),
        LogLevel::Error => error!(plugin = %plugin_id, "{}", message),
    }

    let Some(db) = db else { return };

    let severity = match level {
        LogLevel::Debug | LogLevel::Info => crate::event_log::Severity::Info,
        LogLevel::Warn => crate::event_log::Severity::Warn,
        LogLevel::Error => crate::event_log::Severity::Error,
    };
    let level_str = match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    };

    let event = crate::event_log::EventLog {
        event_type: "plugin.log".to_string(),
        severity,
        actor_did: None,
        subject: Some(plugin_id.to_string()),
        detail: serde_json::json!({
            "level": level_str,
            "message": message,
        }),
    };

    tokio::spawn(async move {
        crate::event_log::log_event(&db, event, db_backend).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_str_known_values() {
        assert!(matches!("debug".parse::<LogLevel>(), Ok(LogLevel::Debug)));
        assert!(matches!("DEBUG".parse::<LogLevel>(), Ok(LogLevel::Debug)));
        assert!(matches!("info".parse::<LogLevel>(), Ok(LogLevel::Info)));
        assert!(matches!("INFO".parse::<LogLevel>(), Ok(LogLevel::Info)));
        assert!(matches!("warn".parse::<LogLevel>(), Ok(LogLevel::Warn)));
        assert!(matches!("warning".parse::<LogLevel>(), Ok(LogLevel::Warn)));
        assert!(matches!("WARN".parse::<LogLevel>(), Ok(LogLevel::Warn)));
        assert!(matches!("error".parse::<LogLevel>(), Ok(LogLevel::Error)));
        assert!(matches!("ERROR".parse::<LogLevel>(), Ok(LogLevel::Error)));
    }

    #[test]
    fn test_log_level_from_str_unknown_defaults_to_info() {
        assert!(matches!("trace".parse::<LogLevel>(), Ok(LogLevel::Info)));
        assert!(matches!("".parse::<LogLevel>(), Ok(LogLevel::Info)));
        assert!(matches!("unknown".parse::<LogLevel>(), Ok(LogLevel::Info)));
    }

    #[test]
    fn test_log_does_not_panic() {
        // With db=None, only the tracing path runs. Verifies each level does not panic.
        let backend = crate::db::DatabaseBackend::Sqlite;
        log(
            "test-plugin",
            LogLevel::Debug,
            "debug message",
            None,
            backend,
        );
        log("test-plugin", LogLevel::Info, "info message", None, backend);
        log("test-plugin", LogLevel::Warn, "warn message", None, backend);
        log(
            "test-plugin",
            LogLevel::Error,
            "error message",
            None,
            backend,
        );
    }
}
