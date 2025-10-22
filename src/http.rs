// src/sqli/http_client.rs
use crate::sqli::config::SqliConfig;
use reqwest::{Client, Response};
use std::sync::Arc;
use std::time::Duration;

pub struct HttpClient {
    client: Client,
    _config: Arc<SqliConfig>,
}

impl HttpClient {
    pub fn new(config: Arc<SqliConfig>) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent(&config.user_agent)
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .build()?;

        Ok(Self {
            client,
            _config: config,
        })
    }

    pub async fn get(&self, url: &str) -> Result<Response, Box<dyn std::error::Error>> {
        Ok(self.client.get(url).send().await?)
    }

    pub async fn post(&self, url: &str, body: String) -> Result<Response, Box<dyn std::error::Error>> {
        Ok(self.client.post(url).body(body).send().await?)
    }
}