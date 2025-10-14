// src/http.rs - HTTP security analysis module
use reqwest::{Client, redirect::Policy};
use std::time::{Duration, Instant};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HttpOptions {
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub timeout_secs: u64,
    pub user_agent: String,
    pub analyze_security: bool,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            follow_redirects: true,
            max_redirects: 10,
            timeout_secs: 30,
            user_agent: "Mozilla/5.0 (Security Scanner)".to_string(),
            analyze_security: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpResult {
    pub url: String,
    pub final_url: String,
    pub status_code: u16,
    pub content_length: u64,
    pub duration_ms: u64,
    pub redirected: bool,
    pub headers: HashMap<String, String>,
    pub security_analysis: Option<SecurityAnalysis>,
}

#[derive(Debug, Clone)]
pub struct SecurityAnalysis {
    pub risk_score: u32,
    pub missing_headers: Vec<String>,
    pub insecure_headers: Vec<String>,
    pub vulnerabilities: Vec<String>,
}

pub async fn http_get_secure(url: &str, options: HttpOptions) -> Result<HttpResult, String> {
    let start = Instant::now();

    // Normalize URL
    let normalized_url = if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("https://{}", url)
    } else {
        url.to_string()
    };

    // Configure redirect policy
    let redirect_policy = if options.follow_redirects {
        Policy::limited(options.max_redirects)
    } else {
        Policy::none()
    };

    // Build client
    let client = Client::builder()
        .timeout(Duration::from_secs(options.timeout_secs))
        .redirect(redirect_policy)
        .user_agent(&options.user_agent)
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| format!("Failed to build client: {}", e))?;

    // Make request
    let response = client.get(&normalized_url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    let duration_ms = start.elapsed().as_millis() as u64;
    let final_url = response.url().to_string();
    let status_code = response.status().as_u16();

    // Extract headers
    let mut headers = HashMap::new();
    for (key, value) in response.headers() {
        if let Ok(val_str) = value.to_str() {
            headers.insert(key.to_string(), val_str.to_string());
        }
    }

    let content_length = response.content_length().unwrap_or(0);
    let redirected = normalized_url != final_url;

    // Perform security analysis if requested
    let security_analysis = if options.analyze_security {
        Some(analyze_security(&headers, &normalized_url, &final_url, status_code))
    } else {
        None
    };

    Ok(HttpResult {
        url: normalized_url,
        final_url,
        status_code,
        content_length,
        duration_ms,
        redirected,
        headers,
        security_analysis,
    })
}

fn analyze_security(
    headers: &HashMap<String, String>,
    original_url: &str,
    final_url: &str,
    status_code: u16,
) -> SecurityAnalysis {
    let mut risk_score = 0u32;
    let mut missing_headers = Vec::new();
    let mut insecure_headers = Vec::new();
    let mut vulnerabilities = Vec::new();

    // Check for missing security headers
    let security_headers = vec![
        ("strict-transport-security", 15),
        ("x-frame-options", 10),
        ("x-content-type-options", 8),
        ("content-security-policy", 15),
        ("x-xss-protection", 5),
        ("referrer-policy", 5),
        ("permissions-policy", 8),
    ];

    for (header_name, score) in security_headers {
        if !headers.contains_key(header_name) {
            risk_score += score;
            missing_headers.push(format!("{} (risk: +{})", header_name, score));
        }
    }

    // Check for information disclosure headers
    if let Some(value) = headers.get("x-powered-by") {
        risk_score += 5;
        insecure_headers.push(format!("x-powered-by: {} (exposes technology)", value));
    }

    if let Some(value) = headers.get("server") {
        if value.contains('/') || value.len() > 20 {
            risk_score += 5;
            insecure_headers.push(format!("server: {} (too verbose)", value));
        }
    }

    // Check for weak HSTS
    if let Some(value) = headers.get("strict-transport-security") {
        if !value.contains("max-age") || !value.contains("includeSubDomains") {
            risk_score += 8;
            insecure_headers.push("strict-transport-security: weak configuration".to_string());
        }
    }

    // Check for HTTP usage
    if original_url.starts_with("http://") {
        risk_score += 20;
        vulnerabilities.push("CRITICAL: Using insecure HTTP protocol".to_string());
    }

    // Check for HTTPS downgrade
    if original_url.starts_with("https://") && final_url.starts_with("http://") {
        risk_score += 25;
        vulnerabilities.push("CRITICAL: HTTPS to HTTP downgrade detected".to_string());
    }

    // Check for cross-domain redirect
    if let (Ok(orig), Ok(fin)) = (
        url::Url::parse(original_url),
        url::Url::parse(final_url)
    ) {
        if orig.host_str() != fin.host_str() {
            risk_score += 10;
            vulnerabilities.push(format!(
                "MEDIUM: Cross-domain redirect ({} -> {})",
                orig.host_str().unwrap_or(""),
                fin.host_str().unwrap_or("")
            ));
        }
    }

    // Check for debug headers
    let debug_headers = vec!["x-debug", "x-aspnet-version", "x-aspnetmvc-version"];
    for debug_header in debug_headers {
        if let Some(value) = headers.get(debug_header) {
            risk_score += 8;
            vulnerabilities.push(format!("MEDIUM: Debug header exposed - {}: {}", debug_header, value));
        }
    }

    // Check error pages
    if status_code >= 400 && status_code < 600 {
        if let Some(content_type) = headers.get("content-type") {
            if content_type.contains("text/html") {
                vulnerabilities.push(format!("INFO: Error page returned ({})", status_code));
            }
        }
    }

    SecurityAnalysis {
        risk_score,
        missing_headers,
        insecure_headers,
        vulnerabilities,
    }
}

// Simple HTTP GET without security analysis
pub async fn http_get_simple(url: &str, timeout_secs: u64) -> Result<HttpResult, String> {
    let options = HttpOptions {
        follow_redirects: true,
        max_redirects: 10,
        timeout_secs,
        user_agent: "Mozilla/5.0".to_string(),
        analyze_security: false,
    };

    http_get_secure(url, options).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http_get() {
        let options = HttpOptions::default();
        let result = http_get_secure("https://example.com", options).await;
        assert!(result.is_ok());
    }
}