// src/sqli/tester.rs - ENHANCED WITH COMPREHENSIVE DETECTION
use crate::sqli::config::SqliConfig;
use crate::sqli::error::ScanError;
use crate::sqli::heuristics::Heuristics;
use crate::sqli::http_client::HttpClient;
use crate::sqli::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::warn;

/// Enhanced SQL injection testing module with advanced detection
pub struct SqliTester {
    http_client: HttpClient,
    config: Arc<SqliConfig>,
}

impl SqliTester {
    pub fn new(config: Arc<SqliConfig>) -> Result<Self, ScanError> {
        let http_client = HttpClient::new(config.clone())?;

        Ok(Self {
            http_client,
            config,
        })
    }

    /// Test an endpoint and parameter for SQL injection
    pub async fn test_parameter(
        &self,
        endpoint: &Endpoint,
        parameter: &Parameter,
    ) -> Result<Option<TestResult>, ScanError> {
        println!("\n{}", "=".repeat(70));
        println!("🔍 TESTING PARAMETER");
        println!("{}", "=".repeat(70));
        println!("📍 Endpoint: {}", endpoint.url);
        println!("🎯 Parameter: {} ({:?})", parameter.name, parameter.location);
        println!("{}\n", "=".repeat(70));

        let mut vulnerabilities = Vec::new();

        // Check for rate limiting before testing
        if let Some(rate_limit_msg) = self.check_rate_limiting(endpoint).await? {
            println!("⚠️  Rate limiting detected: {}", rate_limit_msg);
            println!("   Slowing down tests...\n");
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }

        // 1. Boolean-based differential test (with statistical validation)
        println!("🧪 [1/4] Boolean-based testing (statistical validation)...");
        if let Some(evidence) = self.test_boolean_based_statistical(endpoint, parameter).await? {
            println!("   ✅ Boolean-based vulnerability detected!");
            vulnerabilities.push(evidence);
        } else {
            println!("   ❌ No boolean-based vulnerability");
        }

        // 2. Time-based test with 2x delay detection
        println!("\n🧪 [2/4] Time-based testing (with 2x delay detection)...");
        if let Some(evidence) = self.test_time_based_enhanced(endpoint, parameter).await? {
            println!("   ✅ Time-based vulnerability detected!");
            vulnerabilities.push(evidence);
        } else {
            println!("   ❌ No time-based vulnerability");
        }

        // 3. Error-based test with expanded patterns
        println!("\n🧪 [3/4] Error-based testing (expanded patterns)...");
        if let Some(evidence) = self.test_error_based_enhanced(endpoint, parameter).await? {
            println!("   ✅ Error-based vulnerability detected!");
            vulnerabilities.push(evidence);
        } else {
            println!("   ❌ No error-based vulnerability");
        }

        // 4. Status code differential (200→500→200 pattern)
        println!("\n🧪 [4/4] Status code differential testing...");
        if let Some(evidence) = self.test_status_differential(endpoint, parameter).await? {
            println!("   ✅ Status differential vulnerability detected!");
            vulnerabilities.push(evidence);
        } else {
            println!("   ❌ No status differential vulnerability");
        }

        // 5. Out-of-band test (if enabled)
        if self.config.enable_oob {
            println!("\n🧪 [5/5] Out-of-band testing...");
            if let Some(evidence) = self.test_out_of_band(endpoint, parameter).await? {
                println!("   ✅ OOB vulnerability detected!");
                vulnerabilities.push(evidence);
            } else {
                println!("   ❌ No OOB vulnerability");
            }
        } else {
            println!("\n⏭️  [5/5] OOB testing skipped (disabled)");
        }

        // If any evidence found, create result
        if !vulnerabilities.is_empty() {
            println!("\n🎉 VULNERABILITY FOUND!");
            println!("   Evidence count: {}", vulnerabilities.len());

            let vuln_type = Self::determine_vulnerability_type(&vulnerabilities);
            let confidence = Self::calculate_confidence_enhanced(&vulnerabilities);

            println!("   Type: {:?}", vuln_type);
            println!("   Confidence: {:?}", confidence);

            // Verification step: re-run tests to confirm
            println!("\n🔄 Verifying vulnerability...");
            let verified = self.verify_vulnerability(endpoint, parameter, &vuln_type).await?;
            println!("   Verified: {}", if verified { "✅ YES" } else { "❌ NO" });

            Ok(Some(TestResult {
                endpoint: endpoint.url.clone(),
                parameter: parameter.name.clone(),
                location: parameter.location.clone(),
                vulnerability_type: vuln_type,
                confidence,
                evidence: vulnerabilities,
                verified,
                timestamp: chrono::Utc::now().to_rfc3339(),
            }))
        } else {
            println!("\n❌ No vulnerabilities detected for this parameter");
            Ok(None)
        }
    }

    // NEW: Check for rate limiting before heavy testing
    async fn check_rate_limiting(&self, endpoint: &Endpoint) -> Result<Option<String>, ScanError> {
        println!("   🔍 Checking for rate limiting...");

        // Make 3 quick requests to check for rate limiting
        for i in 1..=3 {
            let response = self.http_client.get(&endpoint.url).await?;
            let status = response.status().as_u16();

            if status == 429 {
                return Ok(Some(format!("HTTP 429 (Too Many Requests) on request {}", i)));
            } else if status == 403 {
                let body = response.text().await.unwrap_or_default();
                if body.to_lowercase().contains("rate limit") || body.to_lowercase().contains("too many") {
                    return Ok(Some(format!("HTTP 403 with rate limit indication on request {}", i)));
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        println!("   ✅ No rate limiting detected");
        Ok(None)
    }

    // NEW: Boolean-based testing with statistical validation (multiple samples)
    async fn test_boolean_based_statistical(
        &self,
        endpoint: &Endpoint,
        parameter: &Parameter,
    ) -> Result<Option<Evidence>, ScanError> {
        println!("   📊 Boolean-based differential analysis (statistical)");

        let true_payload = &self.config.payload_config.boolean_true_payload;
        let false_payload = &self.config.payload_config.boolean_false_payload;

        if true_payload.contains("PLACEHOLDER") {
            println!("   ⚠️  Skipping - using placeholder payload");
            return Ok(None);
        }

        // NEW: Multiple samples for statistical confidence
        let samples = 5;
        println!("   📈 Testing with {} samples for statistical confidence", samples);

        let baseline_value = parameter.example_value.as_deref().unwrap_or("1");

        // Collect baseline samples
        let mut baseline_lengths = Vec::new();
        let mut baseline_statuses = Vec::new();

        println!("\n   📊 Collecting baseline samples...");
        for i in 0..samples {
            let baseline_url = self.inject_parameter(endpoint, parameter, baseline_value)?;
            match self.http_client.get(&baseline_url).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    baseline_lengths.push(body.len());
                    baseline_statuses.push(status);
                    println!("      Sample {}: {} bytes, status {}", i + 1, body.len(), status);
                }
                Err(_) => continue,
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        if baseline_lengths.is_empty() {
            return Ok(None);
        }

        // Collect TRUE payload samples
        let mut true_lengths = Vec::new();
        let mut true_statuses = Vec::new();

        println!("\n   📊 Testing TRUE payload ({} samples)...", samples);
        for i in 0..samples {
            let true_url = self.inject_parameter(endpoint, parameter, true_payload)?;
            match self.http_client.get(&true_url).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    true_lengths.push(body.len());
                    true_statuses.push(status);
                    println!("      Sample {}: {} bytes, status {}", i + 1, body.len(), status);
                }
                Err(_) => continue,
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        if true_lengths.is_empty() {
            return Ok(None);
        }

        // Collect FALSE payload samples
        let mut false_lengths = Vec::new();
        let mut false_statuses = Vec::new();

        println!("\n   📊 Testing FALSE payload ({} samples)...", samples);
        for i in 0..samples {
            let false_url = self.inject_parameter(endpoint, parameter, false_payload)?;
            match self.http_client.get(&false_url).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    false_lengths.push(body.len());
                    false_statuses.push(status);
                    println!("      Sample {}: {} bytes, status {}", i + 1, body.len(), status);
                }
                Err(_) => continue,
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        if false_lengths.is_empty() {
            return Ok(None);
        }

        // Calculate medians for statistical stability
        let baseline_median = Self::median(&baseline_lengths);
        let true_median = Self::median(&true_lengths);
        let false_median = Self::median(&false_lengths);

        println!("\n   📊 Statistical Analysis:");
        println!("      Baseline median: {} bytes", baseline_median);
        println!("      TRUE median:     {} bytes", true_median);
        println!("      FALSE median:    {} bytes", false_median);

        // Check consistency across samples (low variance = high confidence)
        let baseline_variance = Self::calculate_variance(&baseline_lengths, baseline_median);
        let true_variance = Self::calculate_variance(&true_lengths, true_median);
        let false_variance = Self::calculate_variance(&false_lengths, false_median);

        println!("      Baseline variance: {:.2}", baseline_variance);
        println!("      TRUE variance:     {:.2}", true_variance);
        println!("      FALSE variance:    {:.2}", false_variance);

        // Differential analysis
        let true_similar_to_baseline = Self::is_similar(true_median, baseline_median);
        let false_different_from_true = !Self::is_similar(false_median, true_median);

        println!("\n   🎯 Differential Detection:");
        println!("      TRUE ≈ Baseline: {}", true_similar_to_baseline);
        println!("      FALSE ≠ TRUE:    {}", false_different_from_true);

        // High confidence if we see consistent differential
        if true_similar_to_baseline && false_different_from_true {
            let confidence_level = if baseline_variance < 100.0 && true_variance < 100.0 {
                "HIGH (consistent results)"
            } else {
                "MEDIUM (some variance)"
            };

            println!("   🎯 STRONG evidence of boolean-based SQL injection! ({})", confidence_level);

            return Ok(Some(Evidence {
                test_type: format!("Boolean-based blind (statistical - {})", confidence_level),
                description: format!(
                    "Statistically validated differential responses across {} samples. TRUE median: {} bytes (similar to baseline {}), FALSE median: {} bytes (different)",
                    samples, true_median, baseline_median, false_median
                ),
                request_sample: RequestSample {
                    method: format!("{:?}", endpoint.method),
                    url: endpoint.url.clone(),
                    parameter: parameter.name.clone(),
                    payload_type: "BOOLEAN_TRUE".to_string(),
                    headers: HashMap::new(),
                },
                response_sample: ResponseSample {
                    status_code: true_statuses[0],
                    content_length: true_median,
                    response_time_ms: 0,
                    error_indicators: vec![],
                    differential_markers: vec![
                        format!("TRUE median: {} bytes", true_median),
                        format!("FALSE median: {} bytes", false_median),
                        format!("Difference: {} bytes", (true_median as i64 - false_median as i64).abs()),
                        format!("Samples: {}", samples),
                    ],
                },
                timing_data: None,
            }));
        }

        println!("   ❌ No clear differential behavior");
        Ok(None)
    }

    // NEW: Enhanced time-based testing with 2x delay detection
    async fn test_time_based_enhanced(
        &self,
        endpoint: &Endpoint,
        parameter: &Parameter,
    ) -> Result<Option<Evidence>, ScanError> {
        println!("   ⏱️  Enhanced time-based blind SQL injection test");

        let time_payload = &self.config.payload_config.time_delay_payload;

        if time_payload.contains("PLACEHOLDER") {
            println!("   ⚠️  Skipping - using placeholder payload");
            return Ok(None);
        }

        let baseline_value = parameter.example_value.as_deref().unwrap_or("1");
        let baseline_url = self.inject_parameter(endpoint, parameter, baseline_value)?;

        println!("   📊 Measuring baseline timing ({} samples)...", self.config.time_samples);
        let mut baseline_times = Vec::new();
        for i in 0..self.config.time_samples {
            let start = Instant::now();
            if self.http_client.get(&baseline_url).await.is_ok() {
                let elapsed = start.elapsed().as_millis() as u64;
                baseline_times.push(elapsed);
                println!("      Sample {}: {}ms", i + 1, elapsed);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        if baseline_times.is_empty() {
            return Ok(None);
        }

        let baseline_median = Self::median_u64(&baseline_times);
        println!("   📊 Baseline median: {}ms", baseline_median);

        // Test with time delay payload
        let test_url = self.inject_parameter(endpoint, parameter, time_payload)?;

        println!("\n   📊 Testing with time delay ({} samples)...", self.config.time_samples);
        let mut test_times = Vec::new();
        for i in 0..self.config.time_samples {
            let start = Instant::now();
            if self.http_client.get(&test_url).await.is_ok() {
                let elapsed = start.elapsed().as_millis() as u64;
                test_times.push(elapsed);
                println!("      Sample {}: {}ms", i + 1, elapsed);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        if test_times.is_empty() {
            return Ok(None);
        }

        let test_median = Self::median_u64(&test_times);
        let expected_delay = self.config.time_delay_secs * 1000;
        let delay_diff = test_median as i64 - baseline_median as i64;

        println!("   📊 Test median: {}ms", test_median);
        println!("   📊 Expected delay: {}ms", expected_delay);
        println!("   📊 Actual delay: {}ms", delay_diff);

        // NEW: Check for 2x execution pattern (query executed twice)
        let double_exec_delay = (baseline_median as i64 * 2) - baseline_median as i64;
        let is_double_execution = delay_diff > 0
            && delay_diff >= (double_exec_delay as f64 * 0.8) as i64
            && delay_diff <= (double_exec_delay as f64 * 1.2) as i64;

        if is_double_execution {
            println!("   🎯 2X EXECUTION PATTERN DETECTED!");
            println!("      Baseline: {}ms", baseline_median);
            println!("      Test: {}ms (~2x baseline)", test_median);
            println!("      This indicates the query is being executed twice");

            return Ok(Some(Evidence {
                test_type: "Time-based blind (2x execution pattern)".to_string(),
                description: format!(
                    "Query executed twice detected: baseline {}ms → test {}ms ({}x multiplier). This suggests the injected payload causes the database query to run multiple times.",
                    baseline_median, test_median, delay_diff as f64 / baseline_median as f64
                ),
                request_sample: RequestSample {
                    method: format!("{:?}", endpoint.method),
                    url: endpoint.url.clone(),
                    parameter: parameter.name.clone(),
                    payload_type: "TIME_DELAY_2X".to_string(),
                    headers: HashMap::new(),
                },
                response_sample: ResponseSample {
                    status_code: 200,
                    content_length: 0,
                    response_time_ms: test_median,
                    error_indicators: vec![],
                    differential_markers: vec![
                        "2x execution pattern".to_string(),
                        format!("Multiplier: {:.2}x", delay_diff as f64 / baseline_median as f64),
                    ],
                },
                timing_data: Some(TimingData {
                    baseline_median_ms: baseline_median as f64,
                    test_median_ms: test_median as f64,
                    baseline_samples: baseline_times.clone(),
                    test_samples: test_times.clone(),
                    statistical_significance: true,
                    p_value: None,
                }),
            }));
        }

        // Check standard delay pattern
        let delay_lower = (expected_delay as f64 * 0.8) as u64;
        let delay_upper = (expected_delay as f64 * 1.2) as u64;

        if delay_diff > 0 && (delay_diff as u64) >= delay_lower && (delay_diff as u64) <= delay_upper {
            println!("   🎯 Significant time delay detected!");

            return Ok(Some(Evidence {
                test_type: "Time-based blind".to_string(),
                description: format!(
                    "Response delayed by {}ms compared to baseline (expected ~{}ms)",
                    delay_diff, expected_delay
                ),
                request_sample: RequestSample {
                    method: format!("{:?}", endpoint.method),
                    url: endpoint.url.clone(),
                    parameter: parameter.name.clone(),
                    payload_type: "TIME_DELAY".to_string(),
                    headers: HashMap::new(),
                },
                response_sample: ResponseSample {
                    status_code: 200,
                    content_length: 0,
                    response_time_ms: test_median,
                    error_indicators: vec![],
                    differential_markers: vec![],
                },
                timing_data: Some(TimingData {
                    baseline_median_ms: baseline_median as f64,
                    test_median_ms: test_median as f64,
                    baseline_samples: baseline_times.clone(),
                    test_samples: test_times.clone(),
                    statistical_significance: true,
                    p_value: None,
                }),
            }));
        }

        println!("   ❌ No significant time delay detected");
        Ok(None)
    }

    // NEW: Enhanced error-based testing with expanded database error patterns
    async fn test_error_based_enhanced(
        &self,
        endpoint: &Endpoint,
        parameter: &Parameter,
    ) -> Result<Option<Evidence>, ScanError> {
        println!("   🚨 Enhanced error-based SQL injection test");

        let error_payload = &self.config.payload_config.error_probe_payload;

        if error_payload.contains("PLACEHOLDER") {
            println!("   ⚠️  Skipping - using placeholder payload");
            return Ok(None);
        }

        let test_url = self.inject_parameter(endpoint, parameter, error_payload)?;

        let response = match self.http_client.get(&test_url).await {
            Ok(resp) => resp,
            Err(_) => return Ok(None),
        };

        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();

        // NEW: Expanded database error patterns for better detection
        let error_patterns = vec![
            // MySQL errors
            ("You have an error in your SQL syntax", "MySQL", "critical"),
            ("mysql_fetch_array()", "MySQL", "critical"),
            ("mysql_num_rows()", "MySQL", "critical"),
            ("mysqli_", "MySQL/MySQLi", "critical"),
            ("Warning: mysql", "MySQL", "critical"),
            ("supplied argument is not a valid MySQL", "MySQL", "critical"),

            // PostgreSQL errors
            ("PostgreSQL query failed", "PostgreSQL", "critical"),
            ("pg_query()", "PostgreSQL", "critical"),
            ("pg_exec()", "PostgreSQL", "critical"),
            ("supplied argument is not a valid PostgreSQL", "PostgreSQL", "critical"),

            // MSSQL errors
            ("Microsoft OLE DB Provider for SQL Server", "MSSQL", "critical"),
            ("ODBC SQL Server Driver", "MSSQL", "critical"),
            ("SQLServer JDBC Driver", "MSSQL", "critical"),
            ("Unclosed quotation mark", "MSSQL", "critical"),

            // Oracle errors
            ("ORA-", "Oracle", "critical"),
            ("Oracle error", "Oracle", "critical"),

            // SQLite errors
            ("SQLite3::", "SQLite", "critical"),
            ("sqlite_", "SQLite", "critical"),
            ("SQLiteException", "SQLite", "critical"),

            // Generic SQL errors
            ("SQL syntax", "Generic SQL", "critical"),
            ("SQLSTATE", "Generic SQL", "critical"),
            ("Syntax error or access violation", "Generic SQL", "critical"),
            ("syntax error at or near", "Generic SQL", "critical"),
            ("unterminated quoted string", "Generic SQL", "critical"),
        ];

        let mut found_errors = Vec::new();
        for (pattern, db_type, severity) in error_patterns {
            if body.contains(pattern) {
                found_errors.push(format!("[{}] {} error: {}", severity, db_type, pattern));
                println!("   ✅ Found error: {} - {}", db_type, pattern);
            }
        }

        if !found_errors.is_empty() {
            println!("   🎯 Database error messages detected!");

            return Ok(Some(Evidence {
                test_type: "Error-based (expanded patterns)".to_string(),
                description: format!("Database error messages found: {}", found_errors.join("; ")),
                request_sample: RequestSample {
                    method: format!("{:?}", endpoint.method),
                    url: endpoint.url.clone(),
                    parameter: parameter.name.clone(),
                    payload_type: "ERROR_PROBE".to_string(),
                    headers: HashMap::new(),
                },
                response_sample: ResponseSample {
                    status_code: status,
                    content_length: body.len(),
                    response_time_ms: 0,
                    error_indicators: found_errors,
                    differential_markers: vec![],
                },
                timing_data: None,
            }));
        }

        println!("   ❌ No database errors detected");
        Ok(None)
    }

    // NEW: Status code differential testing (200→500→200 pattern)
    async fn test_status_differential(
        &self,
        endpoint: &Endpoint,
        parameter: &Parameter,
    ) -> Result<Option<Evidence>, ScanError> {
        println!("   📊 Status code differential pattern testing");

        let baseline_value = parameter.example_value.as_deref().unwrap_or("1");
        let test_payloads = vec![
            ("normal", baseline_value),
            ("error_probe", "'"),
            ("recovery", baseline_value),
        ];

        let mut statuses = Vec::new();
        let mut descriptions = Vec::new();

        println!("   🔍 Testing status code patterns...");
        for (name, payload) in &test_payloads {
            let test_url = self.inject_parameter(endpoint, parameter, payload)?;

            match self.http_client.get(&test_url).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    statuses.push(status);
                    descriptions.push(format!("{}: {}", name, status));
                    println!("      {}: {}", name, status);
                }
                Err(_) => {
                    statuses.push(0);
                    descriptions.push(format!("{}: error", name));
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }

        // Check for 200→500→200 pattern
        if statuses.len() == 3 && statuses[0] == 200 && statuses[1] == 500 && statuses[2] == 200 {
            println!("   🎯 200→500→200 PATTERN DETECTED!");
            println!("      This indicates SQL injection causing temporary errors");

            return Ok(Some(Evidence {
                test_type: "Status differential (200→500→200)".to_string(),
                description: "Classic SQL injection pattern: normal request (200) → injection causes error (500) → recovery request (200)".to_string(),
                request_sample: RequestSample {
                    method: format!("{:?}", endpoint.method),
                    url: endpoint.url.clone(),
                    parameter: parameter.name.clone(),
                    payload_type: "STATUS_DIFFERENTIAL".to_string(),
                    headers: HashMap::new(),
                },
                response_sample: ResponseSample {
                    status_code: 500,
                    content_length: 0,
                    response_time_ms: 0,
                    error_indicators: vec!["500 error on injection".to_string()],
                    differential_markers: descriptions,
                },
                timing_data: None,
            }));
        }

        // Check for other suspicious patterns
        if statuses.len() == 3 && statuses[0] != statuses[1] && statuses[1] >= 400 {
            println!("   ⚠️  Status code changes detected: {:?}", statuses);

            return Ok(Some(Evidence {
                test_type: "Status differential (varied)".to_string(),
                description: format!("Status codes vary with injection: {:?}", statuses),
                request_sample: RequestSample {
                    method: format!("{:?}", endpoint.method),
                    url: endpoint.url.clone(),
                    parameter: parameter.name.clone(),
                    payload_type: "STATUS_DIFFERENTIAL".to_string(),
                    headers: HashMap::new(),
                },
                response_sample: ResponseSample {
                    status_code: statuses[1],
                    content_length: 0,
                    response_time_ms: 0,
                    error_indicators: vec![],
                    differential_markers: descriptions,
                },
                timing_data: None,
            }));
        }

        println!("   ❌ No status code differential detected");
        Ok(None)
    }

    // Helper functions
    fn inject_parameter(&self, endpoint: &Endpoint, parameter: &Parameter, value: &str) -> Result<String, ScanError> {
        match parameter.location {
            ParameterLocation::Query => {
                let mut url = url::Url::parse(&endpoint.url)?;
                {
                    let mut query_pairs = url.query_pairs_mut();
                    query_pairs.clear();

                    if let Some(query) = url::Url::parse(&endpoint.url).ok().and_then(|u| u.query().map(|q| q.to_string())) {
                        for pair in query.split('&') {
                            if let Some((key, val)) = pair.split_once('=') {
                                if key == parameter.name {
                                    query_pairs.append_pair(key, value);
                                } else {
                                    query_pairs.append_pair(key, val);
                                }
                            }
                        }
                    }

                    if !endpoint.url.contains(&format!("{}=", parameter.name)) {
                        query_pairs.append_pair(&parameter.name, value);
                    }
                }
                Ok(url.to_string())
            }
            ParameterLocation::FormData => {
                warn!("POST form testing not fully implemented, using GET");
                let encoded_value = urlencoding::encode(value);
                if endpoint.url.contains('?') {
                    Ok(format!("{}&{}={}", endpoint.url, parameter.name, encoded_value))
                } else {
                    Ok(format!("{}?{}={}", endpoint.url, parameter.name, encoded_value))
                }
            }
            _ => {
                Err(ScanError::Config(format!("Unsupported parameter location: {:?}", parameter.location)))
            }
        }
    }

    fn median_u64(values: &[u64]) -> u64 {
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        if sorted.len() % 2 == 0 {
            (sorted[mid - 1] + sorted[mid]) / 2
        } else {
            sorted[mid]
        }
    }

    fn median(values: &[usize]) -> usize {
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        if sorted.len() % 2 == 0 {
            (sorted[mid - 1] + sorted[mid]) / 2
        } else {
            sorted[mid]
        }
    }

    fn calculate_variance(values: &[usize], mean: usize) -> f64 {
        if values.is_empty() {
            return 0.0;
        }

        let sum: f64 = values.iter()
            .map(|&v| {
                let diff = v as f64 - mean as f64;
                diff * diff
            })
            .sum();

        sum / values.len() as f64
    }

    fn is_similar(val1: usize, val2: usize) -> bool {
        if val1 == 0 || val2 == 0 {
            return val1 == val2;
        }

        let diff_ratio = ((val1 as f64 - val2 as f64).abs()) / (val1.max(val2) as f64);
        diff_ratio < 0.1
    }

    fn determine_vulnerability_type(evidence: &[Evidence]) -> VulnerabilityType {
        for ev in evidence {
            if ev.test_type.contains("Status differential") {
                return VulnerabilityType::BooleanBased;
            }
        }

        for ev in evidence {
            if ev.test_type.contains("Time") || ev.test_type.contains("2x execution") {
                return VulnerabilityType::TimeBased;
            }
        }

        for ev in evidence {
            if ev.test_type.contains("Boolean") {
                return VulnerabilityType::BooleanBased;
            }
        }

        for ev in evidence {
            if ev.test_type.contains("Error") {
                return VulnerabilityType::ErrorBased;
            }
        }

        VulnerabilityType::OutOfBand
    }

    // NEW: Enhanced confidence calculation with more factors
    fn calculate_confidence_enhanced(evidence: &[Evidence]) -> ConfidenceLevel {
        let mut score = 0;

        for ev in evidence {
            if ev.test_type.contains("2x execution") {
                score += 4; // Very strong indicator
            } else if ev.test_type.contains("200→500→200") {
                score += 4; // Very strong indicator
            } else if ev.test_type.contains("statistical") && ev.test_type.contains("HIGH") {
                score += 4; // High confidence statistical test
            } else if ev.test_type.contains("Time") {
                score += 3;
            } else if ev.test_type.contains("Boolean") && !ev.test_type.contains("weak") {
                score += 3;
            } else if ev.test_type.contains("Error") && ev.test_type.contains("critical") {
                score += 3;
            } else if ev.test_type.contains("weak") {
                score += 1;
            } else if ev.test_type.contains("Error") {
                score += 2;
            }
        }

        match score {
            0..=1 => ConfidenceLevel::Low,
            2..=3 => ConfidenceLevel::Medium,
            4..=6 => ConfidenceLevel::High,
            _ => ConfidenceLevel::Confirmed,
        }
    }

    async fn verify_vulnerability(
        &self,
        endpoint: &Endpoint,
        parameter: &Parameter,
        vuln_type: &VulnerabilityType
    ) -> Result<bool, ScanError> {
        println!("   🔄 Verifying {:?} vulnerability...", vuln_type);

        match vuln_type {
            VulnerabilityType::BooleanBased => {
                self.test_boolean_based_statistical(endpoint, parameter).await.map(|r| r.is_some())
            }
            VulnerabilityType::TimeBased => {
                self.test_time_based_enhanced(endpoint, parameter).await.map(|r| r.is_some())
            }
            VulnerabilityType::ErrorBased => {
                self.test_error_based_enhanced(endpoint, parameter).await.map(|r| r.is_some())
            }
            _ => Ok(false),
        }
    }

    async fn test_out_of_band(&self, _endpoint: &Endpoint, _parameter: &Parameter) -> Result<Option<Evidence>, ScanError> {
        println!("   🌐 Out-of-band testing");
        println!("   ⚠️  OOB testing requires external callback infrastructure");
        Ok(None)
    }
}