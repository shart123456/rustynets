// src/sqli/config.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Configuration for SQL injection scanner
#[derive(Debug, Clone)]
pub struct SqliConfig {
    pub target: String,
    pub max_concurrency: usize,
    pub max_rps: u32,
    pub timeout_secs: u64,
    pub max_depth: usize,
    pub enable_oob: bool,
    pub oob_host: Option<String>,
    pub time_delay_secs: u64,
    pub time_samples: usize,
    pub payload_config: PayloadConfig,
    pub payload_file: Option<PathBuf>,
    pub user_agent: String,
    pub custom_headers: HashMap<String, String>,
    pub cookies: Option<String>,
    pub follow_redirects: bool,
    pub max_endpoints: usize,
}

impl Default for SqliConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            max_concurrency: 5,
            max_rps: 10,
            timeout_secs: 30,
            max_depth: 3,
            enable_oob: false,
            oob_host: None,
            time_delay_secs: 3,
            time_samples: 5,
            payload_config: PayloadConfig::default(),
            payload_file: None,
            user_agent: "Mozilla/5.0 (Security Scanner)".to_string(),
            custom_headers: HashMap::new(),
            cookies: None,
            follow_redirects: true,
            max_endpoints: 100,
        }
    }
}

/// CRITICAL: Payload configuration uses PLACEHOLDERS ONLY
/// Authorized testers must provide actual test payloads via configuration file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadConfig {
    /// Boolean-based test payloads (PLACEHOLDERS)
    /// Example payloads (supply via config file):
    ///   MySQL: "' OR '1'='1" / "' OR '1'='2"
    ///   PostgreSQL: "' OR 'x'='x" / "' OR 'x'='y"
    pub boolean_true_payload: String,
    pub boolean_false_payload: String,

    /// Time-based test payloads (PLACEHOLDERS)
    /// Example payloads (supply via config file):
    ///   MySQL: "' OR SLEEP(3)--"
    ///   PostgreSQL: "' OR pg_sleep(3)--"
    ///   MSSQL: "'; WAITFOR DELAY '00:00:03'--"
    pub time_delay_payload: String,

    /// Error-probing payload (PLACEHOLDER)
    /// Example: single quote "'"
    pub error_probe_payload: String,

    /// Out-of-band payloads (PLACEHOLDERS)
    /// Example payloads (supply via config file):
    ///   DNS exfiltration attempts
    pub oob_dns_payload: String,
    pub oob_http_payload: String,
}

impl Default for PayloadConfig {
    fn default() -> Self {
        Self {
            // CRITICAL: These are PLACEHOLDERS only
            // Real attack strings are NOT included
            // Authorized testers provide actual payloads via YAML config
            boolean_true_payload: "BOOLEAN_TRUE_PAYLOAD".to_string(),
            boolean_false_payload: "BOOLEAN_FALSE_PAYLOAD".to_string(),
            time_delay_payload: "TIME_DELAY_PAYLOAD".to_string(),
            error_probe_payload: "ERROR_PROBE_PAYLOAD".to_string(),
            oob_dns_payload: "OOB_DNS_PAYLOAD".to_string(),
            oob_http_payload: "OOB_HTTP_PAYLOAD".to_string(),
        }
    }
}

impl SqliConfig {
    pub fn validate(&self) -> Result<(), String> {
        // Validate target URL
        url::Url::parse(&self.target)
            .map_err(|e| format!("Invalid target URL: {}", e))?;

        // Validate OOB configuration
        if self.enable_oob && self.oob_host.is_none() {
            return Err("OOB testing enabled but no OOB host provided".to_string());
        }

        // Enforce safety limits
        if self.time_delay_secs > 5 {
            return Err("Time delay must be ≤ 5 seconds for safety".to_string());
        }

        if self.max_concurrency > 20 {
            return Err("Max concurrency capped at 20 for safety".to_string());
        }

        if self.max_rps > 50 {
            return Err("Max RPS capped at 50 for safety".to_string());
        }

        // Warn about placeholders
        if self.payload_config.boolean_true_payload.contains("PLACEHOLDER") {
            eprintln!("⚠️  WARNING: Using PLACEHOLDER payloads");
            eprintln!("   No real testing will occur without actual payloads");
            eprintln!("   Provide payloads via --payload-file");
        }

        Ok(())
    }

    pub fn load_payloads_from_file(path: &PathBuf) -> Result<PayloadConfig, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read payload file: {}", e))?;

        serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse payload YAML: {}", e))
    }
}