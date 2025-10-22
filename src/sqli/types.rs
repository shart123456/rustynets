use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a discovered endpoint (URL, form, API endpoint)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub url: String,
    pub method: HttpMethod,
    pub endpoint_type: EndpointType,
    pub parameters: Vec<Parameter>,
    pub depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EndpointType {
    Link,
    Form,
    JsonApi,
    XhrEndpoint,
}

/// Represents a parameter that can be tested
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub location: ParameterLocation,
    pub example_value: Option<String>,
    pub required: bool,
    pub param_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ParameterLocation {
    Query,
    FormData,
    JsonBody,
    Header,
    Cookie,
}

/// Test result for a specific parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub endpoint: String,
    pub parameter: String,
    pub location: ParameterLocation,
    pub vulnerability_type: VulnerabilityType,
    pub confidence: ConfidenceLevel,
    pub evidence: Vec<Evidence>,
    pub verified: bool,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnerabilityType {
    BooleanBased,
    TimeBased,
    ErrorBased,
    OutOfBand,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
    Confirmed,
}

/// Evidence for a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub test_type: String,
    pub description: String,
    pub request_sample: RequestSample,
    pub response_sample: ResponseSample,
    pub timing_data: Option<TimingData>,
}

/// Sanitized request sample (no full payload strings that extract data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSample {
    pub method: String,
    pub url: String,
    pub parameter: String,
    pub payload_type: String, // e.g., "BOOLEAN_TRUE", not the actual payload
    pub headers: HashMap<String, String>,
}

/// Sanitized response sample (no sensitive data dumps)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseSample {
    pub status_code: u16,
    pub content_length: usize,
    pub response_time_ms: u64,
    pub error_indicators: Vec<String>,
    pub differential_markers: Vec<String>,
}

/// Timing statistics for time-based tests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingData {
    pub baseline_median_ms: f64,
    pub test_median_ms: f64,
    pub baseline_samples: Vec<u64>,
    pub test_samples: Vec<u64>,
    pub statistical_significance: bool,
    pub p_value: Option<f64>,
}

/// Complete scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub target: String,
    pub scan_start: String,
    pub scan_end: String,
    pub endpoints_discovered: usize,
    pub parameters_tested: usize,
    pub vulnerabilities: Vec<TestResult>,
    pub summary: ScanSummary,
    pub configuration: ScanConfigSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_requests: usize,
    pub high_confidence: usize,
    pub medium_confidence: usize,
    pub low_confidence: usize,
    pub verified_count: usize,
    pub boolean_based: usize,
    pub time_based: usize,
    pub error_based: usize,
    pub oob_based: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfigSummary {
    pub max_concurrency: usize,
    pub max_rps: u32,
    pub oob_enabled: bool,
    pub payloads_source: String,
}

/// Passive check result
#[derive(Debug, Clone)]
pub struct PassiveFindings {
    pub has_error_messages: bool,
    pub has_stack_traces: bool,
    pub database_identifiers: Vec<String>,
    pub reflection_points: Vec<String>,
}