// src/fuzz.rs - Web Fuzzing Module
use reqwest::Client;
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Debug, Clone)]
pub struct FuzzOptions {
    pub timeout_secs: u64,
    pub user_agent: String,
    pub max_concurrent: usize,
    pub follow_redirects: bool,
    pub status_filter: Option<Vec<u16>>,  // Filter by status codes
    pub size_filter: Option<(u64, u64)>,  // Filter by content size range (min, max)
    pub match_pattern: Option<String>,     // Match response content
    pub hide_pattern: Option<String>,      // Hide matching responses
}

impl Default for FuzzOptions {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            user_agent: "FlashFuzz/1.0".to_string(),
            max_concurrent: 50,
            follow_redirects: false,
            status_filter: None,
            size_filter: None,
            match_pattern: None,
            hide_pattern: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FuzzResult {
    pub url: String,
    pub status_code: u16,
    pub content_length: u64,
    pub duration_ms: u64,
    pub found: bool,
}

/// Fuzz directories/files on a target URL
pub async fn fuzz_directories(
    base_url: &str,
    wordlist: Vec<String>,
    options: FuzzOptions,
) -> Vec<FuzzResult> {
    let client = Arc::new(
        Client::builder()
            .timeout(Duration::from_secs(options.timeout_secs))
            .redirect(if options.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .user_agent(&options.user_agent)
            .build()
            .expect("Failed to create HTTP client"),
    );

    let semaphore = Arc::new(Semaphore::new(options.max_concurrent));
    let base_url = Arc::new(normalize_base_url(base_url));
    let options = Arc::new(options);

    let mut tasks = Vec::new();

    for word in wordlist {
        let client = Arc::clone(&client);
        let base_url = Arc::clone(&base_url);
        let options = Arc::clone(&options);
        let semaphore = Arc::clone(&semaphore);

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.ok()?;
            fuzz_single_path(&client, &base_url, &word, &options).await
        });

        tasks.push(task);
    }

    let mut results = Vec::new();
    for task in tasks {
        if let Ok(Some(result)) = task.await {
            if should_include_result(&result, &options) {
                results.push(result);
            }
        }
    }

    // Sort by status code, then by URL
    results.sort_by(|a, b| {
        a.status_code
            .cmp(&b.status_code)
            .then(a.url.cmp(&b.url))
    });

    results
}

/// Fuzz subdomains
pub async fn fuzz_subdomains(
    domain: &str,
    wordlist: Vec<String>,
    options: FuzzOptions,
) -> Vec<FuzzResult> {
    let mut subdomain_urls = Vec::new();

    for word in wordlist {
        let subdomain_url = format!("https://{}.{}", word, domain);
        subdomain_urls.push(subdomain_url);
    }

    // Reuse directory fuzzing logic
    fuzz_urls(subdomain_urls, options).await
}

/// Fuzz a list of complete URLs
pub async fn fuzz_urls(
    urls: Vec<String>,
    options: FuzzOptions,
) -> Vec<FuzzResult> {
    let client = Arc::new(
        Client::builder()
            .timeout(Duration::from_secs(options.timeout_secs))
            .redirect(if options.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .user_agent(&options.user_agent)
            .build()
            .expect("Failed to create HTTP client"),
    );

    let semaphore = Arc::new(Semaphore::new(options.max_concurrent));
    let options = Arc::new(options);

    let mut tasks = Vec::new();

    for url in urls {
        let client = Arc::clone(&client);
        let _options = Arc::clone(&options);
        let semaphore = Arc::clone(&semaphore);

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.ok()?;

            let start = Instant::now();
            match client.get(&url).send().await {
                Ok(response) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    let status_code = response.status().as_u16();
                    let content_length = response.content_length().unwrap_or(0);

                    Some(FuzzResult {
                        url,
                        status_code,
                        content_length,
                        duration_ms,
                        found: status_code >= 200 && status_code < 300,
                    })
                }
                Err(_) => None,
            }
        });

        tasks.push(task);
    }

    let mut results = Vec::new();
    for task in tasks {
        if let Ok(Some(result)) = task.await {
            if should_include_result(&result, &options) {
                results.push(result);
            }
        }
    }

    results.sort_by(|a, b| {
        a.status_code
            .cmp(&b.status_code)
            .then(a.url.cmp(&b.url))
    });

    results
}

async fn fuzz_single_path(
    client: &Client,
    base_url: &str,
    path: &str,
    _options: &FuzzOptions,
) -> Option<FuzzResult> {
    let url = format!("{}/{}", base_url, path.trim_start_matches('/'));

    let start = Instant::now();
    match client.get(&url).send().await {
        Ok(response) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let status_code = response.status().as_u16();
            let content_length = response.content_length().unwrap_or(0);

            Some(FuzzResult {
                url,
                status_code,
                content_length,
                duration_ms,
                found: status_code >= 200 && status_code < 300,
            })
        }
        Err(_) => None,
    }
}

fn normalize_base_url(url: &str) -> String {
    let mut normalized = url.trim_end_matches('/').to_string();

    if !normalized.starts_with("http://") && !normalized.starts_with("https://") {
        normalized = format!("https://{}", normalized);
    }

    normalized
}

fn should_include_result(result: &FuzzResult, options: &FuzzOptions) -> bool {
    // Filter by status code
    if let Some(ref status_filter) = options.status_filter {
        if !status_filter.contains(&result.status_code) {
            return false;
        }
    }

    // Filter by content size
    if let Some((min_size, max_size)) = options.size_filter {
        if result.content_length < min_size || result.content_length > max_size {
            return false;
        }
    }

    true
}

/// Load wordlist from file or use built-in
pub fn load_wordlist(path: Option<&str>) -> Result<Vec<String>, std::io::Error> {
    if let Some(file_path) = path {
        // Load from file
        let content = std::fs::read_to_string(file_path)?;
        Ok(content
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect())
    } else {
        // Return built-in wordlist
        Ok(get_builtin_wordlist())
    }
}

/// Built-in wordlist for quick testing
fn get_builtin_wordlist() -> Vec<String> {
    vec![
        // Common directories
        "admin".to_string(),
        "login".to_string(),
        "dashboard".to_string(),
        "api".to_string(),
        "backup".to_string(),
        "config".to_string(),
        "uploads".to_string(),
        "assets".to_string(),
        "images".to_string(),
        "js".to_string(),
        "css".to_string(),
        "static".to_string(),
        "test".to_string(),
        "dev".to_string(),
        "tmp".to_string(),
        "temp".to_string(),
        ".git".to_string(),
        ".env".to_string(),
        ".htaccess".to_string(),
        "robots.txt".to_string(),
        "sitemap.xml".to_string(),

        // Common files
        "index.html".to_string(),
        "index.php".to_string(),
        "config.php".to_string(),
        "database.sql".to_string(),
        "backup.zip".to_string(),
        "readme.md".to_string(),
        "phpinfo.php".to_string(),

        // API endpoints
        "api/v1".to_string(),
        "api/v2".to_string(),
        "graphql".to_string(),
        "swagger".to_string(),
        "docs".to_string(),
    ]
}

/// Generate wordlist with common extensions
pub fn generate_wordlist_with_extensions(
    base_words: Vec<String>,
    extensions: Vec<&str>,
) -> Vec<String> {
    let mut wordlist = base_words.clone();

    for word in &base_words {
        for ext in &extensions {
            wordlist.push(format!("{}.{}", word, ext));
        }
    }

    wordlist
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        assert_eq!(normalize_base_url("example.com"), "https://example.com");
        assert_eq!(normalize_base_url("http://example.com/"), "http://example.com");
        assert_eq!(normalize_base_url("https://example.com/path/"), "https://example.com/path");
    }

    #[test]
    fn test_builtin_wordlist() {
        let wordlist = get_builtin_wordlist();
        assert!(!wordlist.is_empty());
        assert!(wordlist.contains(&"admin".to_string()));
    }

    #[test]
    fn test_generate_extensions() {
        let base = vec!["test".to_string()];
        let extensions = vec!["php", "html", "js"];
        let result = generate_wordlist_with_extensions(base, extensions);

        assert!(result.contains(&"test".to_string()));
        assert!(result.contains(&"test.php".to_string()));
        assert!(result.contains(&"test.html".to_string()));
    }
}