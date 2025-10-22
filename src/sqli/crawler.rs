// src/sqli/crawler.rs
use crate::sqli::config::SqliConfig;
use crate::sqli::error::ScanError;
use crate::sqli::http_client::HttpClient;
use crate::sqli::types::{Endpoint, EndpointType, HttpMethod, Parameter, ParameterLocation};
use scraper::{Html, Selector};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use url::Url;

/// Polite, depth-limited web crawler
pub struct Crawler {
    http_client: HttpClient,
    config: Arc<SqliConfig>,
    visited: Arc<Mutex<HashSet<String>>>,
    queue: Arc<Mutex<VecDeque<(String, usize)>>>,
    endpoints: Arc<Mutex<Vec<Endpoint>>>,
}

impl Crawler {
    pub fn new(config: Arc<SqliConfig>) -> Result<Self, ScanError> {
        let http_client = HttpClient::new(config.clone())?;

        Ok(Self {
            http_client,
            config: config.clone(),
            visited: Arc::new(Mutex::new(HashSet::new())),
            queue: Arc::new(Mutex::new(VecDeque::new())),
            endpoints: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Start crawling from target URL
    pub async fn crawl(&self) -> Result<Vec<Endpoint>, ScanError> {
        info!("🕷️ Starting crawl of {}", self.config.target);

        // Parse base URL
        let base_url = Url::parse(&self.config.target)
            .map_err(|e| ScanError::Crawl(format!("Invalid target URL: {}", e)))?;

        // Initialize queue with target
        {
            let mut queue = self.queue.lock().await;
            queue.push_back((self.config.target.clone(), 0));
        }

        // Crawl loop
        while let Some((url, depth)) = {
            let mut queue = self.queue.lock().await;
            queue.pop_front()
        } {
            // Check depth limit
            if depth > self.config.max_depth {
                continue;
            }

            // Check if already visited
            {
                let mut visited = self.visited.lock().await;
                if visited.contains(&url) {
                    continue;
                }
                visited.insert(url.clone());
            }

            // Check endpoint limit
            {
                let endpoints = self.endpoints.lock().await;
                if endpoints.len() >= self.config.max_endpoints && self.config.max_endpoints > 0 {
                    info!("⚠️ Reached max endpoint limit ({})", self.config.max_endpoints);
                    break;
                }
            }

            // Fetch and process page
            match self.process_url(&url, depth, &base_url).await {
                Ok(_) => {
                    debug!("✓ Processed: {}", url);
                }
                Err(e) => {
                    warn!("Failed to process {}: {}", url, e);
                }
            }
        }

        let endpoints = self.endpoints.lock().await;
        info!("✅ Crawl complete. Found {} endpoints", endpoints.len());

        Ok(endpoints.clone())
    }

    async fn process_url(
        &self,
        url: &str,
        depth: usize,
        base_url: &Url,
    ) -> Result<(), ScanError> {
        // Fetch the page
        let response = self.http_client.get(url).await?;

        // Only process HTML responses
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !content_type.contains("text/html") {
            return Ok(());
        }

        let body = response.text().await?;

        // Parse HTML and extract data synchronously before any await
        let (links, forms, api_endpoints) = {
            let document = Html::parse_document(&body);

            // Extract all data synchronously
            let links = self.extract_links_sync(&document, url, depth + 1, base_url);
            let forms = self.extract_forms_sync(&document, url, depth);
            let api_endpoints = self.extract_api_endpoints_sync(&body, base_url, depth);

            (links, forms, api_endpoints)
        }; // document is dropped here, before any await

        // Now store the extracted data (can await here safely)
        {
            let mut endpoints_lock = self.endpoints.lock().await;
            endpoints_lock.extend(links.clone());
            endpoints_lock.extend(forms);
            endpoints_lock.extend(api_endpoints);
        }

        // Queue links for crawling
        {
            let mut queue = self.queue.lock().await;
            for link in links {
                queue.push_back((link.url, link.depth));
            }
        }

        Ok(())
    }

    fn extract_links_sync(
        &self,
        document: &Html,
        current_url: &str,
        next_depth: usize,
        base_url: &Url,
    ) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let link_selector = Selector::parse("a[href]").unwrap();

        for element in document.select(&link_selector) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(absolute_url) = self.resolve_url(href, current_url, base_url) {
                    // Only queue links from same origin
                    if self.is_same_origin(&absolute_url, base_url) {
                        // Extract query parameters
                        let params = self.extract_query_params(&absolute_url);

                        endpoints.push(Endpoint {
                            url: absolute_url,
                            method: HttpMethod::GET,
                            endpoint_type: EndpointType::Link,
                            parameters: params,
                            depth: next_depth,
                        });
                    }
                }
            }
        }

        endpoints
    }

    fn extract_forms_sync(
        &self,
        document: &Html,
        current_url: &str,
        depth: usize,
    ) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();
        let form_selector = Selector::parse("form").unwrap();
        let input_selector = Selector::parse("input, select, textarea").unwrap();

        for form in document.select(&form_selector) {
            let action = form.value().attr("action").unwrap_or("");
            let method = form
                .value()
                .attr("method")
                .unwrap_or("get")
                .to_uppercase();

            // Resolve form action URL
            let form_url = if action.is_empty() {
                current_url.to_string()
            } else {
                match Url::parse(current_url) {
                    Ok(base) => match base.join(action) {
                        Ok(url) => url.to_string(),
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                }
            };

            // Extract form parameters
            let mut parameters = Vec::new();
            for input in form.select(&input_selector) {
                if let Some(name) = input.value().attr("name") {
                    let value = input.value().attr("value").map(|s| s.to_string());
                    let required = input.value().attr("required").is_some();
                    let input_type = input.value().attr("type").map(|s| s.to_string());

                    parameters.push(Parameter {
                        name: name.to_string(),
                        location: if method == "POST" {
                            ParameterLocation::FormData
                        } else {
                            ParameterLocation::Query
                        },
                        example_value: value,
                        required,
                        param_type: input_type,
                    });
                }
            }

            endpoints.push(Endpoint {
                url: form_url,
                method: if method == "POST" {
                    HttpMethod::POST
                } else {
                    HttpMethod::GET
                },
                endpoint_type: EndpointType::Form,
                parameters,
                depth,
            });
        }

        endpoints
    }

    fn extract_api_endpoints_sync(
        &self,
        body: &str,
        base_url: &Url,
        depth: usize,
    ) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        // Simple heuristic: look for common API endpoint patterns in script tags
        let patterns = [
            r#"['"](/api/[^'"]+)['"]"#,
            r#"['"](/v\d+/[^'"]+)['"]"#,
            r#"fetch\(['"]([^'"]+)['"]"#,
            r#"axios\.[a-z]+\(['"]([^'"]+)['"]"#,
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.captures_iter(body) {
                    if let Some(path) = cap.get(1) {
                        if let Ok(api_url) = base_url.join(path.as_str()) {
                            let url_str = api_url.to_string();

                            // Check if same origin
                            if self.is_same_origin(&url_str, base_url) {
                                endpoints.push(Endpoint {
                                    url: url_str,
                                    method: HttpMethod::GET,
                                    endpoint_type: EndpointType::JsonApi,
                                    parameters: vec![],
                                    depth,
                                });
                            }
                        }
                    }
                }
            }
        }

        endpoints
    }

    fn extract_query_params(&self, url: &str) -> Vec<Parameter> {
        let mut params = Vec::new();

        if let Ok(parsed) = Url::parse(url) {
            for (key, value) in parsed.query_pairs() {
                params.push(Parameter {
                    name: key.to_string(),
                    location: ParameterLocation::Query,
                    example_value: Some(value.to_string()),
                    required: false,
                    param_type: None,
                });
            }
        }

        params
    }

    fn resolve_url(&self, href: &str, current_url: &str, base_url: &Url) -> Result<String, ScanError> {
        // Handle absolute URLs
        if href.starts_with("http://") || href.starts_with("https://") {
            return Ok(href.to_string());
        }

        // Handle protocol-relative URLs
        if href.starts_with("//") {
            return Ok(format!("{}:{}", base_url.scheme(), href));
        }

        // Handle fragment-only URLs
        if href.starts_with('#') {
            return Err(ScanError::Crawl("Fragment-only URL".to_string()));
        }

        // Resolve relative URL
        let current = Url::parse(current_url)?;
        let resolved = current.join(href)?;
        Ok(resolved.to_string())
    }

    fn is_same_origin(&self, url: &str, base_url: &Url) -> bool {
        if let Ok(parsed) = Url::parse(url) {
            parsed.scheme() == base_url.scheme()
                && parsed.host_str() == base_url.host_str()
                && parsed.port() == base_url.port()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_param_extraction() {
        let url = "https://example.com/page?id=1&name=test";
        let config = Arc::new(SqliConfig {
            target: "https://example.com".to_string(),
            max_concurrency: 5,
            max_rps: 10,
            timeout_secs: 30,
            max_depth: 2,
            enable_oob: false,
            oob_host: None,
            time_delay_secs: 3,
            time_samples: 5,
            payload_config: crate::sqli::config::PayloadConfig::default(),
            payload_file: None,
            user_agent: "test".to_string(),
            custom_headers: std::collections::HashMap::new(),
            cookies: None,
            follow_redirects: true,
            max_endpoints: 100,
        });

        let crawler = Crawler::new(config).unwrap();
        let params = crawler.extract_query_params(url);

        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "id");
        assert_eq!(params[1].name, "name");
    }
}