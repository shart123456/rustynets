// src/sqli/http_client.rs - FIXED VERSION with proper cookie support
use crate::sqli::config::SqliConfig;
use reqwest::{Client, Response};
use std::sync::Arc;
use std::time::Duration;

/// HTTP client wrapper for SQL injection scanner
pub struct HttpClient {
    client: Client,
    config: Arc<SqliConfig>,
}

impl HttpClient {
    /// Create a new HTTP client with scanner configuration
    pub fn new(config: Arc<SqliConfig>) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent(&config.user_agent)
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .cookie_store(false) // Disable automatic cookie handling, we'll do it manually
            .build()?;

        Ok(Self {
            client,
            config,
        })
    }

    /// Perform an HTTP GET request with proper headers and cookies
    pub async fn get(&self, url: &str) -> Result<Response, Box<dyn std::error::Error>> {
        let mut request = self.client.get(url);

        // Add custom headers
        for (key, value) in &self.config.custom_headers {
            request = request.header(key, value);
        }

        // Add cookies if configured
        if let Some(ref cookies) = self.config.cookies {
            request = request.header("Cookie", cookies);
        }

        Ok(request.send().await?)
    }

    /// Perform an HTTP POST request
    pub async fn post(&self, url: &str, body: String) -> Result<Response, Box<dyn std::error::Error>> {
        let mut request = self.client.post(url).body(body);

        // Add custom headers
        for (key, value) in &self.config.custom_headers {
            request = request.header(key, value);
        }

        // Add cookies if configured
        if let Some(ref cookies) = self.config.cookies {
            request = request.header("Cookie", cookies);
        }

        Ok(request.send().await?)
    }

    /// Perform an HTTP POST request with form data
    pub async fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let mut request = self.client.post(url).form(form);

        // Add custom headers
        for (key, value) in &self.config.custom_headers {
            request = request.header(key, value);
        }

        // Add cookies if configured
        if let Some(ref cookies) = self.config.cookies {
            request = request.header("Cookie", cookies);
        }

        Ok(request.send().await?)
    }

    /// Perform an HTTP POST request with JSON body
    pub async fn post_json(
        &self,
        url: &str,
        json: &serde_json::Value,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let mut request = self.client.post(url).json(json);

        // Add custom headers
        for (key, value) in &self.config.custom_headers {
            request = request.header(key, value);
        }

        // Add cookies if configured
        if let Some(ref cookies) = self.config.cookies {
            request = request.header("Cookie", cookies);
        }

        Ok(request.send().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_config() -> Arc<SqliConfig> {
        Arc::new(SqliConfig {
            target: "https://example.com".to_string(),
            max_concurrency: 5,
            max_rps: 10,
            timeout_secs: 30,
            max_depth: 3,
            enable_oob: false,
            oob_host: None,
            time_delay_secs: 3,
            time_samples: 5,
            payload_config: crate::sqli::config::PayloadConfig::default(),
            payload_file: None,
            user_agent: "test-agent".to_string(),
            custom_headers: HashMap::new(),
            cookies: Some("PHPSESSID=test123; security=low".to_string()),
            follow_redirects: true,
            max_endpoints: 100,
        })
    }

    #[test]
    fn test_http_client_creation() {
        let config = create_test_config();
        let client = HttpClient::new(config);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_http_get_with_cookies() {
        let config = create_test_config();
        let client = HttpClient::new(config).unwrap();

        // This will make a real request - use a reliable test endpoint
        let result = client.get("https://httpbin.org/cookies").await;
        assert!(result.is_ok());
    }
}