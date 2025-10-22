// src/error.rs
//! Unified error type for netool
//!
//! This module provides a centralized error type for all netool operations
//! across different modules (DNS, HTTP, fuzzing, SQL injection scanning).

use std::fmt;

/// Main error type for all netool operations
#[derive(Debug)]
pub enum NetoolError {
    /// DNS dig operation error
    Dig(String),

    /// Web fuzzing error
    Fuzz(String),

    /// SQL injection scanning error
    Sqli(String),

    /// I/O error (file operations)
    Io(std::io::Error),

    /// Network/connectivity error
    Network(String),

    /// HTTP request/response error
    Http(String),

    /// Parsing error (URL, JSON, etc.)
    Parse(String),

    /// Configuration error
    Config(String),
}

impl std::error::Error for NetoolError {}

impl fmt::Display for NetoolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NetoolError::Dig(s) => write!(f, "DNS dig error: {}", s),
            NetoolError::Fuzz(s) => write!(f, "Fuzzing error: {}", s),
            NetoolError::Sqli(s) => write!(f, "SQL injection scan error: {}", s),
            NetoolError::Io(e) => write!(f, "I/O error: {}", e),
            NetoolError::Network(s) => write!(f, "Network error: {}", s),
            NetoolError::Http(s) => write!(f, "HTTP error: {}", s),
            NetoolError::Parse(s) => write!(f, "Parse error: {}", s),
            NetoolError::Config(s) => write!(f, "Configuration error: {}", s),
        }
    }
}

// Automatic conversion from std::io::Error
impl From<std::io::Error> for NetoolError {
    fn from(e: std::io::Error) -> Self {
        NetoolError::Io(e)
    }
}

// Automatic conversion from reqwest::Error
impl From<reqwest::Error> for NetoolError {
    fn from(e: reqwest::Error) -> Self {
        NetoolError::Http(e.to_string())
    }
}

// Automatic conversion from url::ParseError
impl From<url::ParseError> for NetoolError {
    fn from(e: url::ParseError) -> Self {
        NetoolError::Parse(e.to_string())
    }
}

// Automatic conversion from serde_json::Error
impl From<serde_json::Error> for NetoolError {
    fn from(e: serde_json::Error) -> Self {
        NetoolError::Parse(format!("JSON parse error: {}", e))
    }
}

// Automatic conversion from serde_yaml::Error
impl From<serde_yaml::Error> for NetoolError {
    fn from(e: serde_yaml::Error) -> Self {
        NetoolError::Parse(format!("YAML parse error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dig_error() {
        let error = NetoolError::Dig("Invalid record type".to_string());
        assert_eq!(error.to_string(), "DNS dig error: Invalid record type");
    }

    #[test]
    fn test_fuzz_error() {
        let error = NetoolError::Fuzz("Wordlist not found".to_string());
        assert_eq!(error.to_string(), "Fuzzing error: Wordlist not found");
    }

    #[test]
    fn test_sqli_error() {
        let error = NetoolError::Sqli("Authorization required".to_string());
        assert_eq!(error.to_string(), "SQL injection scan error: Authorization required");
    }

    #[test]
    fn test_io_error() {
        let error = NetoolError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found"
        ));
        assert!(error.to_string().contains("I/O error"));
    }

    #[test]
    fn test_network_error() {
        let error = NetoolError::Network("Connection timeout".to_string());
        assert_eq!(error.to_string(), "Network error: Connection timeout");
    }

    #[test]
    fn test_http_error() {
        let error = NetoolError::Http("404 Not Found".to_string());
        assert_eq!(error.to_string(), "HTTP error: 404 Not Found");
    }

    #[test]
    fn test_parse_error() {
        let error = NetoolError::Parse("Invalid URL format".to_string());
        assert_eq!(error.to_string(), "Parse error: Invalid URL format");
    }

    #[test]
    fn test_config_error() {
        let error = NetoolError::Config("Invalid timeout value".to_string());
        assert_eq!(error.to_string(), "Configuration error: Invalid timeout value");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied");
        let netool_error: NetoolError = io_error.into();
        assert!(matches!(netool_error, NetoolError::Io(_)));
    }

    #[test]
    fn test_url_parse_error_conversion() {
        let parse_error = url::Url::parse("not a valid url").unwrap_err();
        let netool_error: NetoolError = parse_error.into();
        assert!(matches!(netool_error, NetoolError::Parse(_)));
    }

    #[test]
    fn test_error_trait_implemented() {
        let error = NetoolError::Dig("Test".to_string());
        let _: &dyn std::error::Error = &error; // Verify Error trait is implemented
    }

    #[test]
    fn test_display_formatting() {
        let errors = vec![
            NetoolError::Dig("test".to_string()),
            NetoolError::Fuzz("test".to_string()),
            NetoolError::Sqli("test".to_string()),
            NetoolError::Network("test".to_string()),
            NetoolError::Http("test".to_string()),
            NetoolError::Parse("test".to_string()),
            NetoolError::Config("test".to_string()),
        ];

        for error in errors {
            let display = error.to_string();
            assert!(!display.is_empty());
            assert!(display.contains("error") || display.contains("Error"));
        }
    }
}