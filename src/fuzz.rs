// fuzz.rs - ENHANCED Advanced web fuzzing module
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{RwLock, Semaphore};
use regex::Regex;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct FuzzOptions {
    pub timeout_secs: u64,
    pub max_concurrent: usize,
    pub status_filter: Option<Vec<u16>>,
    pub show_errors: bool,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub extensions: Vec<String>,
    pub recursive: bool,
    pub max_depth: usize,
    pub baseline_detection: bool,
    pub detect_double_execution: bool,  // NEW: Detect 2x delay patterns
    pub statistical_validation: bool,    // NEW: Use multiple samples for validation
}

impl Default for FuzzOptions {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            max_concurrent: 50,
            status_filter: None,
            show_errors: false,
            user_agent: "Mozilla/5.0 (Fuzzer)".to_string(),
            follow_redirects: true,
            extensions: vec![],
            recursive: false,
            max_depth: 3,
            baseline_detection: true,
            detect_double_execution: true,
            statistical_validation: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FuzzResult {
    pub url: String,
    pub status_code: u16,
    pub content_length: usize,
    pub duration_ms: u128,
    pub findings: Vec<String>,
    pub rate_limited: bool,              // NEW: Rate limiting detected
    pub execution_pattern: Option<ExecutionPattern>, // NEW: Double execution detection
}

// NEW: Track execution patterns
#[derive(Debug, Clone)]
pub struct ExecutionPattern {
    pub pattern_type: String,
    pub baseline_time: u128,
    pub test_time: u128,
    pub ratio: f64,
    pub confidence: String,
}

#[derive(Clone)]
pub struct BaselineDetector {
    baseline_length: usize,
    baseline_hash: u64,
}

impl BaselineDetector {
    pub async fn new(client: &Client, base_url: &str) -> Self {
        // Test with random string to get baseline 404 response
        let random = Uuid::new_v4().to_string();
        let test_url = format!("{}/{}", base_url, random);

        println!("[*] Establishing baseline with random path...");

        if let Ok(response) = client.get(&test_url).send().await {
            if let Ok(body) = response.text().await {
                let baseline = Self {
                    baseline_length: body.len(),
                    baseline_hash: Self::calculate_hash(&body),
                };
                println!("[*] Baseline: {} bytes, hash: {}", baseline.baseline_length, baseline.baseline_hash);
                return baseline;
            }
        }

        Self {
            baseline_length: 0,
            baseline_hash: 0,
        }
    }

    pub fn is_similar(&self, body: &str) -> bool {
        let length_diff = (body.len() as i32 - self.baseline_length as i32).abs();
        let hash = Self::calculate_hash(body);

        // If length is very similar and hash matches, likely same page (custom 404)
        length_diff < 100 && hash == self.baseline_hash
    }

    fn calculate_hash(s: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }
}

// NEW: Enhanced rate limiter with detection
pub struct AdaptiveRateLimiter {
    current_delay: Arc<RwLock<Duration>>,
    error_count: Arc<RwLock<usize>>,
    rate_limit_detected: Arc<RwLock<bool>>,
}

impl AdaptiveRateLimiter {
    pub fn new() -> Self {
        Self {
            current_delay: Arc::new(RwLock::new(Duration::from_millis(0))),
            error_count: Arc::new(RwLock::new(0)),
            rate_limit_detected: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn wait(&self) {
        let delay = *self.current_delay.read().await;
        if delay > Duration::from_millis(0) {
            tokio::time::sleep(delay).await;
        }
    }

    pub async fn on_success(&self) {
        // Decrease delay on success
        let mut delay = self.current_delay.write().await;
        if *delay > Duration::from_millis(0) {
            *delay = delay.saturating_sub(Duration::from_millis(10));
        }

        // Reset error count
        let mut errors = self.error_count.write().await;
        *errors = 0;
    }

    // NEW: Enhanced error handling with rate limit detection
    pub async fn on_error(&self, status_code: Option<u16>) {
        // Check for rate limiting status codes
        if let Some(status) = status_code {
            if status == 429 || status == 403 {
                let mut rate_limited = self.rate_limit_detected.write().await;
                *rate_limited = true;
                println!("[!] Rate limiting detected (status {})", status);
            }
        }

        // Increase delay on errors
        let mut errors = self.error_count.write().await;
        *errors += 1;

        if *errors > 5 {
            let mut delay = self.current_delay.write().await;
            *delay += Duration::from_millis(100);
            println!("[!] Rate limiting detected, slowing down to {}ms delay", delay.as_millis());
        }
    }

    pub async fn is_rate_limited(&self) -> bool {
        *self.rate_limit_detected.read().await
    }
}

// NEW: Status code pattern detector
pub struct StatusPatternDetector {
    pattern_history: Arc<RwLock<Vec<StatusEvent>>>,
}

#[derive(Debug, Clone)]
struct StatusEvent {
    url: String,
    status: u16,
    timestamp: Instant,
}

impl StatusPatternDetector {
    pub fn new() -> Self {
        Self {
            pattern_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn record_status(&self, url: &str, status: u16) {
        let mut history = self.pattern_history.write().await;
        history.push(StatusEvent {
            url: url.to_string(),
            status,
            timestamp: Instant::now(),
        });

        // Keep only last 100 events
        if history.len() > 100 {
            history.remove(0);
        }
    }

    // NEW: Detect 200→500→200 pattern (indicates SQL injection or similar issues)
    pub async fn detect_error_pattern(&self, url: &str) -> Option<String> {
        let history = self.pattern_history.read().await;

        // Get events for this URL
        let url_events: Vec<&StatusEvent> = history
            .iter()
            .filter(|e| e.url == url)
            .collect();

        if url_events.len() >= 3 {
            let last_three: Vec<u16> = url_events.iter()
                .rev()
                .take(3)
                .map(|e| e.status)
                .collect();

            // Check for 200→500→200 pattern
            if last_three.len() == 3 {
                if last_three[0] == 200 && last_three[1] == 500 && last_three[2] == 200 {
                    return Some("200→500→200 pattern detected (potential SQL injection)".to_string());
                }

                // Check for other suspicious patterns
                if last_three[0] >= 400 && last_three[1] == 200 && last_three[2] >= 400 {
                    return Some("Error→Success→Error pattern (unstable endpoint)".to_string());
                }
            }
        }

        None
    }
}

/// Load wordlist from file or use built-in
pub async fn load_wordlist(path: Option<&str>) -> Result<Vec<String>, std::io::Error> {
    if let Some(file_path) = path {
        load_wordlist_from_file(file_path).await
    } else {
        Ok(get_builtin_wordlist())
    }
}

async fn load_wordlist_from_file(path: &str) -> Result<Vec<String>, std::io::Error> {
    let file = File::open(path).await?;
    let reader = BufReader::new(file);
    let mut wordlist = Vec::new();
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let word = line.trim().to_string();
        if !word.is_empty() && !word.starts_with('#') {
            wordlist.push(word);
        }
    }

    Ok(wordlist)
}

fn get_builtin_wordlist() -> Vec<String> {
    vec![
        "admin", "login", "test", "backup", "api", "uploads", "images",
        "css", "js", "data", "config", "setup", "install", "db", "sql",
        "phpinfo", "info", "readme", "changelog", "TODO", "docs",
        "private", "secret", "old", "new", "tmp", "temp", "cache",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Build HTTP client with options
fn build_client(options: &FuzzOptions) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(options.timeout_secs))
        .redirect(if options.follow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .user_agent(&options.user_agent)
        .build()
        .unwrap()
}

/// Fuzz directories with enhanced detection
pub async fn fuzz_directories(
    base_url: &str,
    wordlist: Vec<String>,
    options: FuzzOptions,
) -> Vec<FuzzResult> {
    let client = build_client(&options);

    // Establish baseline if enabled
    let baseline = if options.baseline_detection {
        Some(BaselineDetector::new(&client, base_url).await)
    } else {
        None
    };

    let semaphore = Arc::new(Semaphore::new(options.max_concurrent));
    let results_arc = Arc::new(RwLock::new(Vec::new()));
    let rate_limiter = Arc::new(AdaptiveRateLimiter::new());
    let pattern_detector = Arc::new(StatusPatternDetector::new());

    let mut tasks = Vec::new();

    for word in wordlist {
        let client = client.clone();
        let url = format!("{}/{}", base_url.trim_end_matches('/'), word);
        let sem = semaphore.clone();
        let results = results_arc.clone();
        let opts = options.clone();
        let limiter = rate_limiter.clone();
        let baseline_ref = baseline.clone();
        let detector = pattern_detector.clone();

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            limiter.wait().await;

            if let Some(result) = test_url_enhanced(&client, &url, &opts, baseline_ref.as_ref(), &detector).await {
                let mut r = results.write().await;
                r.push(result.clone());

                if result.rate_limited {
                    limiter.on_error(Some(result.status_code)).await;
                } else {
                    limiter.on_success().await;
                }
            } else {
                limiter.on_error(None).await;
            }
        });

        tasks.push(task);
    }

    for task in tasks {
        let _ = task.await;
    }

    let r = results_arc.read().await;
    r.clone()
}

/// Fuzz subdomains
pub async fn fuzz_subdomains(
    domain: &str,
    wordlist: Vec<String>,
    options: FuzzOptions,
) -> Vec<FuzzResult> {
    let client = build_client(&options);
    let semaphore = Arc::new(Semaphore::new(options.max_concurrent));
    let results_arc = Arc::new(RwLock::new(Vec::new()));
    let pattern_detector = Arc::new(StatusPatternDetector::new());

    let mut tasks = Vec::new();

    for word in wordlist {
        let client = client.clone();
        let url = format!("http://{}.{}", word, domain);
        let sem = semaphore.clone();
        let results = results_arc.clone();
        let opts = options.clone();
        let detector = pattern_detector.clone();

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            if let Some(result) = test_url_enhanced(&client, &url, &opts, None, &detector).await {
                let mut r = results.write().await;
                r.push(result);
            }
        });

        tasks.push(task);
    }

    for task in tasks {
        let _ = task.await;
    }

    let r = results_arc.read().await;
    r.clone()
}

/// Fuzz URL parameters
pub async fn fuzz_parameters(
    base_url: &str,
    param_wordlist: Vec<String>,
    options: FuzzOptions,
) -> Vec<FuzzResult> {
    let client = build_client(&options);
    let semaphore = Arc::new(Semaphore::new(options.max_concurrent));
    let results_arc = Arc::new(RwLock::new(Vec::new()));
    let pattern_detector = Arc::new(StatusPatternDetector::new());

    let mut tasks = Vec::new();

    for param in param_wordlist {
        let client = client.clone();
        let base_url = base_url.to_string();
        let sem = semaphore.clone();
        let results = results_arc.clone();
        let opts = options.clone();
        let detector = pattern_detector.clone();

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            // Test parameter with different values
            let test_values = vec!["1", "test", "true", "../", "admin"];

            for value in test_values {
                let separator = if base_url.contains('?') { "&" } else { "?" };
                let test_url = format!("{}{}{}={}", base_url, separator, param, value);

                if let Some(result) = test_url_enhanced(&client, &test_url, &opts, None, &detector).await {
                    let mut r = results.write().await;
                    r.push(result);
                    break; // Found working parameter
                }
            }
        });

        tasks.push(task);
    }

    for task in tasks {
        let _ = task.await;
    }

    let r = results_arc.read().await;
    r.clone()
}

/// Fuzz with file extensions
pub async fn fuzz_with_extensions(
    base_url: &str,
    wordlist: Vec<String>,
    extensions: Vec<String>,
    options: FuzzOptions,
) -> Vec<FuzzResult> {
    let client = build_client(&options);
    let semaphore = Arc::new(Semaphore::new(options.max_concurrent));
    let results_arc = Arc::new(RwLock::new(Vec::new()));
    let pattern_detector = Arc::new(StatusPatternDetector::new());

    let mut tasks = Vec::new();

    for word in wordlist {
        // Test without extension first
        let client_clone = client.clone();
        let url = format!("{}/{}", base_url.trim_end_matches('/'), word);
        let sem = semaphore.clone();
        let results = results_arc.clone();
        let opts = options.clone();
        let detector = pattern_detector.clone();

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            if let Some(result) = test_url_enhanced(&client_clone, &url, &opts, None, &detector).await {
                let mut r = results.write().await;
                r.push(result);
            }
        });
        tasks.push(task);

        // Test with each extension
        for ext in &extensions {
            let client_clone = client.clone();
            let url = format!("{}/{}{}", base_url.trim_end_matches('/'), word, ext);
            let sem = semaphore.clone();
            let results = results_arc.clone();
            let opts = options.clone();
            let detector = pattern_detector.clone();

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();

                if let Some(result) = test_url_enhanced(&client_clone, &url, &opts, None, &detector).await {
                    let mut r = results.write().await;
                    r.push(result);
                }
            });

            tasks.push(task);
        }
    }

    for task in tasks {
        let _ = task.await;
    }

    let r = results_arc.read().await;
    r.clone()
}

/// Recursive fuzzing
pub async fn fuzz_recursive(
    base_url: &str,
    wordlist: Vec<String>,
    options: FuzzOptions,
) -> Vec<FuzzResult> {
    let mut all_results = Vec::new();
    let mut current_depth = 0;
    let mut urls_to_fuzz = vec![base_url.to_string()];
    let mut visited = HashSet::new();

    while current_depth < options.max_depth && !urls_to_fuzz.is_empty() {
        println!("\n[*] Fuzzing depth {}/{}", current_depth + 1, options.max_depth);
        println!("[*] Testing {} URLs at this depth", urls_to_fuzz.len());

        let mut next_urls = Vec::new();

        for url in &urls_to_fuzz {
            if visited.contains(url) {
                continue;
            }
            visited.insert(url.clone());

            let results = fuzz_directories(url, wordlist.clone(), options.clone()).await;

            // Collect directories for next depth
            for result in &results {
                // If it's a directory (redirects, 301, 302, or 200)
                if result.status_code == 301 ||
                   result.status_code == 302 ||
                   result.status_code == 200 {
                    // Only add if it looks like a directory (ends with /)
                    if result.url.ends_with('/') || result.status_code == 301 {
                        next_urls.push(result.url.clone());
                    }
                }
            }

            all_results.extend(results);
        }

        urls_to_fuzz = next_urls;
        current_depth += 1;
    }

    all_results
}

// NEW: Enhanced URL testing with all detection features
async fn test_url_enhanced(
    client: &Client,
    url: &str,
    options: &FuzzOptions,
    baseline: Option<&BaselineDetector>,
    pattern_detector: &StatusPatternDetector,
) -> Option<FuzzResult> {
    // NEW: Statistical validation - test multiple times if enabled
    let samples = if options.statistical_validation { 3 } else { 1 };
    let mut durations = Vec::new();
    let mut status_codes = Vec::new();
    let mut bodies = Vec::new();

    for _ in 0..samples {
        let start = Instant::now();

        match client.get(url).send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let duration = start.elapsed();
                durations.push(duration.as_millis());
                status_codes.push(status);

                // Record status for pattern detection
                pattern_detector.record_status(url, status).await;

                // Filter by status code if specified
                if let Some(ref filter) = options.status_filter {
                    if !filter.contains(&status) {
                        return None;
                    }
                }

                // Get response body
                if let Ok(body) = response.text().await {
                    bodies.push(body);
                } else {
                    return None;
                }
            }
            Err(e) => {
                if options.show_errors {
                    eprintln!("[!] Error testing {}: {}", url, e);
                }
                return None;
            }
        }

        // Small delay between samples
        if samples > 1 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    // Calculate median duration for statistical validation
    let median_duration = if durations.len() > 1 {
        let mut sorted = durations.clone();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    } else {
        durations[0]
    };

    let status = status_codes[0];
    let body = &bodies[0];
    let content_length = body.len();

    // NEW: Check for rate limiting
    let rate_limited = status == 429 || status == 403;
    if rate_limited {
        println!("[!] Rate limiting detected on {}", url);
    }

    // Check baseline detection
    if let Some(detector) = baseline {
        if detector.is_similar(body) {
            // This is likely a custom 404 page
            return None;
        }
    }

    // NEW: Detect double execution pattern (2x delay)
    let execution_pattern = if options.detect_double_execution && durations.len() >= 2 {
        detect_double_execution(&durations)
    } else {
        None
    };

    // Analyze response for interesting content
    let mut findings = analyze_response_enhanced(body, url);

    // Check for status code patterns
    if let Some(pattern) = pattern_detector.detect_error_pattern(url).await {
        findings.push(format!("[critical] {}", pattern));
    }

    // Add execution pattern finding
    if let Some(ref pattern) = execution_pattern {
        findings.push(format!("[timing] {} - {}x execution detected ({}ms → {}ms)",
            pattern.pattern_type, pattern.ratio, pattern.baseline_time, pattern.test_time));
    }

    Some(FuzzResult {
        url: url.to_string(),
        status_code: status,
        content_length,
        duration_ms: median_duration,
        findings,
        rate_limited,
        execution_pattern,
    })
}

// NEW: Detect 2x delay pattern indicating double query execution
fn detect_double_execution(durations: &[u128]) -> Option<ExecutionPattern> {
    if durations.len() < 2 {
        return None;
    }

    let baseline = durations[0];
    let test = durations[1];

    // Check if test duration is roughly 2x baseline (allowing 20% variance)
    let ratio = test as f64 / baseline as f64;

    if ratio >= 1.8 && ratio <= 2.2 {
        return Some(ExecutionPattern {
            pattern_type: "Double Execution".to_string(),
            baseline_time: baseline,
            test_time: test,
            ratio,
            confidence: "High".to_string(),
        });
    }

    // Check for other suspicious patterns
    if ratio >= 2.5 && ratio <= 3.5 {
        return Some(ExecutionPattern {
            pattern_type: "Triple Execution".to_string(),
            baseline_time: baseline,
            test_time: test,
            ratio,
            confidence: "Medium".to_string(),
        });
    }

    None
}

// NEW: Enhanced response analysis with more database error patterns
pub fn analyze_response_enhanced(body: &str, url: &str) -> Vec<String> {
    let mut findings = Vec::new();

    // Enhanced keyword detection with severity
    let keywords = [
        // Critical database indicators
        ("password", "high"),
        ("api_key", "high"),
        ("secret", "high"),
        ("private_key", "high"),

        // Database error patterns - EXPANDED
        ("sql syntax", "critical"),
        ("mysql_fetch", "critical"),
        ("mysqli_", "critical"),
        ("pg_query", "critical"),
        ("sqlite_", "critical"),
        ("ORA-", "critical"),
        ("SQLSTATE", "critical"),
        ("Unclosed quotation", "critical"),
        ("You have an error in your SQL", "critical"),
        ("Warning: mysql", "critical"),
        ("PostgreSQL query failed", "critical"),
        ("Microsoft OLE DB Provider for SQL Server", "critical"),
        ("Syntax error or access violation", "critical"),

        // Other security indicators
        ("token", "medium"),
        ("admin", "medium"),
        ("debug", "low"),
        ("error", "low"),
        ("exception", "low"),
        ("database", "medium"),
    ];

    let body_lower = body.to_lowercase();
    for (keyword, severity) in &keywords {
        if body_lower.contains(keyword) {
            findings.push(format!("[{}] Keyword: {}", severity, keyword));
        }
    }

    // Check for emails
    if let Ok(email_regex) = Regex::new(r"[\w\.-]+@[\w\.-]+\.\w+") {
        for email in email_regex.find_iter(body).take(3) {
            findings.push(format!("Email: {}", email.as_str()));
        }
    }

    // Check for potential API endpoints
    if body.contains("/api/") {
        findings.push("Potential API endpoint".to_string());
    }

    // NEW: More comprehensive SQL injection indicators
    let sql_patterns = vec![
        (r"(?i)SQL syntax.*?error", "SQL syntax error"),
        (r"(?i)mysql_num_rows", "MySQL function exposure"),
        (r"(?i)supplied argument.*?mysql", "MySQL error"),
        (r"(?i)pg_query\(\)", "PostgreSQL function exposure"),
        (r"(?i)unterminated.*?string", "Unterminated string (SQL)"),
        (r"ORA-\d{5}", "Oracle error code"),
    ];

    for (pattern, description) in sql_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(body) {
                findings.push(format!("[critical] {}", description));
            }
        }
    }

    // Check for stack traces
    if body.contains("Stack trace:") || body.contains("Traceback") {
        findings.push("[medium] Stack trace exposed".to_string());
    }

    // Check for JavaScript in unexpected places
    if body.contains("<script>") && !url.contains(".js") {
        findings.push("[medium] JavaScript in response".to_string());
    }

    findings
}

// Export helper functions from original module
pub fn get_common_file_extensions() -> Vec<&'static str> {
    vec![
        ".php", ".asp", ".aspx", ".jsp", ".html", ".htm", ".js", ".css",
        ".txt", ".xml", ".json", ".bak", ".old", ".backup", ".swp", ".tmp",
    ]
}

pub fn get_backup_file_patterns() -> Vec<String> {
    vec![
        "~", ".bak", ".backup", ".old", ".orig", ".save", ".swp",
        ".tmp", "_backup", "_old", "_bak"
    ].iter().map(|s| s.to_string()).collect()
}

pub fn get_common_parameters() -> Vec<String> {
    vec![
        "id", "page", "user", "name", "file", "path", "url", "redirect",
        "query", "search", "q", "cmd", "exec", "action", "view"
    ].iter().map(|s| s.to_string()).collect()
}

pub fn get_common_payloads() -> Vec<String> {
    vec![
        "../", "..\\", "..", "admin", "root", "test", "1", "0", "true", "false"
    ].iter().map(|s| s.to_string()).collect()
}

pub fn generate_wordlist_with_extensions(base_words: Vec<String>, extensions: Vec<&str>) -> Vec<String> {
    let mut result = Vec::new();
    for word in &base_words {
        result.push(word.clone());
        for ext in &extensions {
            result.push(format!("{}{}", word, ext));
        }
    }
    result
}

pub fn generate_permutations(base_words: Vec<String>, extensions: Vec<&str>, max_depth: usize) -> Vec<String> {
    let mut result = base_words.clone();

    for _ in 0..max_depth {
        let current = result.clone();
        for word in &current {
            for ext in &extensions {
                result.push(format!("{}{}", word, ext));
            }
        }
    }

    result.sort();
    result.dedup();
    result
}

pub fn combine_words(words: Vec<String>, separators: Vec<&str>) -> Vec<String> {
    let mut result = Vec::new();

    for i in 0..words.len() {
        for j in i+1..words.len() {
            for sep in &separators {
                result.push(format!("{}{}{}", words[i], sep, words[j]));
                result.push(format!("{}{}{}", words[j], sep, words[i]));
            }
        }
    }

    result.sort();
    result.dedup();
    result
}

pub fn generate_case_variations(word: &str) -> Vec<String> {
    vec![
        word.to_lowercase(),
        word.to_uppercase(),
        format!("{}{}",
            word.chars().next().unwrap().to_uppercase(),
            word.chars().skip(1).collect::<String>()
        ),
    ]
}

pub fn generate_numbered_variations(base_words: Vec<String>, start: usize, end: usize) -> Vec<String> {
    let mut result = Vec::new();

    for word in &base_words {
        for num in start..=end {
            result.push(format!("{}{}", word, num));
            result.push(format!("{}{}", num, word));
        }
    }

    result
}