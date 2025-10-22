// src/sqli/error.rs
//! Error types for the SQL injection scanner module
//!
//! This module provides a unified error type for all scanner operations,
//! including crawling, HTTP requests, parsing, and configuration errors.

use std::fmt;

/// Main error type for SQL injection scanner operations
#[derive(Debug)]
pub enum ScanError {
    /// Error during web crawling operations
    Crawl(String),

    /// HTTP request/response error
    Http(String),

    /// URL or data parsing error
    Parse(String),

    /// Configuration validation error
    Config(String),

    /// I/O error (file operations)
    Io(std::io::Error),
}

impl std::error::Error for ScanError {}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScanError::Crawl(s) => write!(f, "Crawl error: {}", s),
            ScanError::Http(s) => write!(f, "HTTP error: {}", s),
            ScanError::Parse(s) => write!(f, "Parse error: {}", s),
            ScanError::Config(s) => write!(f, "Configuration error: {}", s),
            ScanError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

// Automatic conversion from std::io::Error
impl From<std::io::Error> for ScanError {
    fn from(e: std::io::Error) -> Self {
        ScanError::Io(e)
    }
}

// Automatic conversion from reqwest::Error
impl From<reqwest::Error> for ScanError {
    fn from(e: reqwest::Error) -> Self {
        ScanError::Http(e.to_string())
    }
}

// Automatic conversion from url::ParseError
impl From<url::ParseError> for ScanError {
    fn from(e: url::ParseError) -> Self {
        ScanError::Parse(e.to_string())
    }
}

// Automatic conversion from Box<dyn std::error::Error>
impl From<Box<dyn std::error::Error>> for ScanError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        ScanError::Http(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawl_error() {
        let error = ScanError::Crawl("Test crawl error".to_string());
        assert_eq!(error.to_string(), "Crawl error: Test crawl error");
    }

    #[test]
    fn test_http_error() {
        let error = ScanError::Http("Connection timeout".to_string());
        assert_eq!(error.to_string(), "HTTP error: Connection timeout");
    }

    #[test]
    fn test_parse_error() {
        let error = ScanError::Parse("Invalid URL".to_string());
        assert_eq!(error.to_string(), "Parse error: Invalid URL");
    }

    #[test]
    fn test_config_error() {
        let error = ScanError::Config("Invalid timeout value".to_string());
        assert_eq!(error.to_string(), "Configuration error: Invalid timeout value");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let scan_error: ScanError = io_error.into();
        assert!(matches!(scan_error, ScanError::Io(_)));
    }

    #[test]
    fn test_url_parse_error_conversion() {
        let parse_error = url::Url::parse("not a valid url").unwrap_err();
        let scan_error: ScanError = parse_error.into();
        assert!(matches!(scan_error, ScanError::Parse(_)));
    }

    #[test]
    fn test_error_trait_implemented() {
        let error = ScanError::Crawl("Test".to_string());
        let _: &dyn std::error::Error = &error; // Verify Error trait is implemented
    }
}