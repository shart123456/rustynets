use crate::sqli::types::PassiveFindings;
use regex::Regex;

/// Passive heuristics for detecting SQL injection indicators
pub struct Heuristics;

impl Heuristics {
    /// Analyze response for passive indicators of SQL injection
    pub fn analyze_response(body: &str, headers: &std::collections::HashMap<String, String>) -> PassiveFindings {
        PassiveFindings {
            has_error_messages: Self::check_error_messages(body),
            has_stack_traces: Self::check_stack_traces(body),
            database_identifiers: Self::find_database_identifiers(body),
            reflection_points: Self::find_reflection_points(body),
        }
    }

    /// Check for database error messages (passive detection only)
    /// NOTE: We do NOT include the actual error strings to avoid being used as an attack tool
    /// This is a placeholder that authorized testers can enhance
    fn check_error_messages(body: &str) -> bool {
        // PLACEHOLDER: Authorized testers should add patterns for:
        // - MySQL errors (e.g., "You have an error in your SQL syntax")
        // - PostgreSQL errors (e.g., "ERROR: syntax error at")
        // - MSSQL errors (e.g., "Unclosed quotation mark")
        // - Oracle errors (e.g., "ORA-")
        // - SQLite errors (e.g., "SQLite3::SQLException")

        let error_patterns = vec![
            r"(?i)SQL",
            r"(?i)mysql",
            r"(?i)syntax\s+error",
            r"(?i)database\s+error",
        ];

        for pattern in error_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(body) {
                    return true;
                }
            }
        }

        false
    }

    /// Check for stack traces indicating verbose error handling
    fn check_stack_traces(body: &str) -> bool {
        let stack_patterns = vec![
            r"at\s+[\w\.]+\([^)]+\.(?:java|php|py|rb|cs):\d+\)",
            r"Traceback\s+\(most recent call last\)",
            r"Stack trace:",
            r"<b>Fatal error</b>:",
        ];

        for pattern in stack_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(body) {
                    return true;
                }
            }
        }

        false
    }

    /// Find database-specific identifiers (table names, column names, etc.)
    fn find_database_identifiers(body: &str) -> Vec<String> {
        let mut identifiers = Vec::new();

        // Common database system indicators
        let db_patterns = vec![
            (r"(?i)MySQL", "MySQL"),
            (r"(?i)PostgreSQL", "PostgreSQL"),
            (r"(?i)Microsoft SQL Server", "MSSQL"),
            (r"(?i)Oracle Database", "Oracle"),
            (r"(?i)SQLite", "SQLite"),
        ];

        for (pattern, name) in db_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(body) {
                    identifiers.push(name.to_string());
                }
            }
        }

        identifiers
    }

    /// Find potential reflection points where input might be echoed
    fn find_reflection_points(body: &str) -> Vec<String> {
        // This is a simplified heuristic
        // In real implementation, track specific test markers
        let reflection_markers = vec![
            r"<!--.*?-->",
            r"<script>.*?</script>",
        ];

        let mut points = Vec::new();
        for pattern in reflection_markers {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(body) {
                    points.push(mat.as_str().chars().take(50).collect());
                }
            }
        }

        points
    }

    /// Calculate confidence score based on multiple indicators
    pub fn calculate_confidence(
        boolean_diff: bool,
        timing_significant: bool,
        error_detected: bool,
        oob_callback: bool,
        verified: bool,
    ) -> crate::sqli::types::ConfidenceLevel {
        let mut score = 0;

        if boolean_diff {
            score += 2;
        }
        if timing_significant {
            score += 3;
        }
        if error_detected {
            score += 1;
        }
        if oob_callback {
            score += 4;
        }
        if verified {
            score += 2;
        }

        match score {
            0..=2 => crate::sqli::types::ConfidenceLevel::Low,
            3..=5 => crate::sqli::types::ConfidenceLevel::Medium,
            6..=8 => crate::sqli::types::ConfidenceLevel::High,
            _ => crate::sqli::types::ConfidenceLevel::Confirmed,
        }
    }
    pub async fn analyze_endpoints(_endpoints: &[crate::sqli::types::Endpoint]) -> Vec<PassiveFindings> {
        // Placeholder - in real implementation, fetch each endpoint and analyze
        // For now, return empty vec to allow compilation
        vec![]
    }

    /// Check if two responses show differential behavior
    pub fn has_differential_response(
        resp1_body: &str,
        resp2_body: &str,
        resp1_status: u16,
        resp2_status: u16,
    ) -> bool {
        // Different status codes
        if resp1_status != resp2_status {
            return true;
        }

        // Significant content length difference (> 10%)
        let len1 = resp1_body.len() as f64;
        let len2 = resp2_body.len() as f64;
        let diff_ratio = (len1 - len2).abs() / len1.max(len2);
        if diff_ratio > 0.1 {
            return true;
        }

        // Different content markers
        let markers = vec![
            "success",
            "error",
            "invalid",
            "not found",
            "exists",
        ];

        for marker in markers {
            let in_resp1 = resp1_body.to_lowercase().contains(marker);
            let in_resp2 = resp2_body.to_lowercase().contains(marker);
            if in_resp1 != in_resp2 {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_detection() {
        let body_with_error = "MySQL error: You have an error in your SQL syntax";
        assert!(Heuristics::check_error_messages(body_with_error));

        let body_normal = "Welcome to our website";
        assert!(!Heuristics::check_error_messages(body_normal));
    }

    #[test]
    fn test_confidence_calculation() {
        use crate::types::ConfidenceLevel;

        // Low confidence
        let conf = Heuristics::calculate_confidence(false, false, true, false, false);
        assert_eq!(conf, ConfidenceLevel::Low);

        // High confidence
        let conf = Heuristics::calculate_confidence(true, true, true, false, true);
        assert_eq!(conf, ConfidenceLevel::High);

        // Confirmed
        let conf = Heuristics::calculate_confidence(true, true, true, true, true);
        assert_eq!(conf, ConfidenceLevel::Confirmed);
    }

    #[test]
    fn test_differential_response() {
        let resp1 = "User found: admin";
        let resp2 = "User not found";

        assert!(Heuristics::has_differential_response(resp1, resp2, 200, 200));
    }
}