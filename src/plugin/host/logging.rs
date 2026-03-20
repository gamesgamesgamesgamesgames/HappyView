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

/// Log a message from a plugin
pub fn log(plugin_id: &str, level: LogLevel, message: &str) {
    match level {
        LogLevel::Debug => debug!(plugin = %plugin_id, "{}", message),
        LogLevel::Info => info!(plugin = %plugin_id, "{}", message),
        LogLevel::Warn => warn!(plugin = %plugin_id, "{}", message),
        LogLevel::Error => error!(plugin = %plugin_id, "{}", message),
    }
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
        // Verify log() runs without panicking for each level
        log("test-plugin", LogLevel::Debug, "debug message");
        log("test-plugin", LogLevel::Info, "info message");
        log("test-plugin", LogLevel::Warn, "warn message");
        log("test-plugin", LogLevel::Error, "error message");
    }
}
