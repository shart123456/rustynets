// src/lib.rs
pub mod error;
pub mod dig;
pub mod fuzz;
pub mod http;
pub mod sqli;



#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::{PyDict, PyList};

#[cfg(feature = "python")]
use std::net::IpAddr;

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (
    target,
    confirm_authorized=false,
    auth_token=None,
    max_concurrency=5,
    rps=10,
    timeout=30,
    max_depth=3,
    enable_oob=false,
    oob_host=None,
    time_delay=3,
    payload_file=None,
))]
fn sqli_scan(
    py: Python,
    target: String,
    confirm_authorized: bool,
    auth_token: Option<String>,
    max_concurrency: usize,
    rps: u32,
    timeout: u64,
    max_depth: usize,
    enable_oob: bool,
    oob_host: Option<String>,
    time_delay: u64,
    payload_file: Option<String>,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        use std::path::PathBuf;

        // CRITICAL: Authorization check
        if !confirm_authorized && auth_token.is_none() {
            return Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                let result = PyDict::new(py);
                result.set_item("success", false)?;
                result.set_item("error", "AUTHORIZATION REQUIRED: Must provide confirm_authorized=True or auth_token")?;
                result.set_item("legal_notice", "This tool is for AUTHORIZED testing only. Unauthorized use is ILLEGAL.")?;
                Ok(result.into())
            });
        }

        // Load payload config
        let payload_config = if let Some(ref path_str) = payload_file {
            let path = PathBuf::from(path_str);
            match crate::sqli::config::SqliConfig::load_payloads_from_file(&path) {
                Ok(config) => config,
                Err(e) => {
                    return Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                        let result = PyDict::new(py);
                        result.set_item("success", false)?;
                        result.set_item("error", format!("Failed to load payload file: {}", e))?;
                        Ok(result.into())
                    });
                }
            }
        } else {
            crate::sqli::config::PayloadConfig::default()
        };

        // Build configuration
        let config = crate::sqli::config::SqliConfig {
            target,
            max_concurrency: max_concurrency.min(20),
            max_rps: rps.min(50),
            timeout_secs: timeout,
            max_depth,
            enable_oob,
            oob_host,
            time_delay_secs: time_delay.min(5),
            time_samples: 5,
            payload_config,
            payload_file: payload_file.map(PathBuf::from),
            user_agent: "netool-python-sqli/1.0".to_string(),
            custom_headers: std::collections::HashMap::new(),
            cookies: None,
            follow_redirects: true,
            max_endpoints: 100,
        };

        // Validate configuration
        if let Err(e) = config.validate() {
            return Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                let result = PyDict::new(py);
                result.set_item("success", false)?;
                result.set_item("error", format!("Configuration error: {}", e))?;
                Ok(result.into())
            });
        }

        // Perform scan
        match crate::sqli::scan_target(config).await {
            Ok(results) => {
                Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let result = PyDict::new(py);
                    result.set_item("success", true)?;
                    result.set_item("target", &results.target)?;
                    result.set_item("scan_start", &results.scan_start)?;
                    result.set_item("scan_end", &results.scan_end)?;
                    result.set_item("endpoints_discovered", results.endpoints_discovered)?;
                    result.set_item("parameters_tested", results.parameters_tested)?;

                    // Convert vulnerabilities
                    let py_vulns = PyList::empty(py);
                    for vuln in results.vulnerabilities {
                        let py_vuln = PyDict::new(py);
                        py_vuln.set_item("endpoint", vuln.endpoint)?;
                        py_vuln.set_item("parameter", vuln.parameter)?;
                        py_vuln.set_item("location", format!("{:?}", vuln.location))?;
                        py_vuln.set_item("vulnerability_type", format!("{:?}", vuln.vulnerability_type))?;
                        py_vuln.set_item("confidence", format!("{:?}", vuln.confidence))?;
                        py_vuln.set_item("verified", vuln.verified)?;
                        py_vuln.set_item("timestamp", vuln.timestamp)?;
                        py_vuln.set_item("evidence_count", vuln.evidence.len())?;
                        py_vulns.append(py_vuln)?;
                    }
                    result.set_item("vulnerabilities", py_vulns)?;

                    // Summary
                    let summary = PyDict::new(py);
                    summary.set_item("total_requests", results.summary.total_requests)?;
                    summary.set_item("high_confidence", results.summary.high_confidence)?;
                    summary.set_item("medium_confidence", results.summary.medium_confidence)?;
                    summary.set_item("low_confidence", results.summary.low_confidence)?;
                    summary.set_item("verified_count", results.summary.verified_count)?;
                    summary.set_item("boolean_based", results.summary.boolean_based)?;
                    summary.set_item("time_based", results.summary.time_based)?;
                    summary.set_item("error_based", results.summary.error_based)?;
                    summary.set_item("oob_based", results.summary.oob_based)?;
                    result.set_item("summary", summary)?;

                    Ok(result.into())
                })
            }
            Err(e) => {
                Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let result = PyDict::new(py);
                    result.set_item("success", false)?;
                    result.set_item("error", e.to_string())?;
                    Ok(result.into())
                })
            }
        }
    })
}

/// Python wrapper for DNS resolve operation
#[cfg(feature = "python")]
#[pyfunction]
#[must_use]
fn dns_resolve(py: Python, domain: String) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        use hickory_resolver::config::*;
        use hickory_resolver::TokioAsyncResolver;

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        match resolver.lookup_ip(&domain).await {
            Ok(response) => {
                let ips: Vec<String> = response.iter().map(|ip| ip.to_string()).collect();
                Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let result = PyDict::new(py);
                    result.set_item("domain", domain)?;
                    result.set_item("ips", ips)?;
                    result.set_item("success", true)?;
                    Ok(result.into())
                })
            }
            Err(e) => {
                Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let result = PyDict::new(py);
                    result.set_item("domain", domain)?;
                    result.set_item("error", e.to_string())?;
                    result.set_item("success", false)?;
                    Ok(result.into())
                })
            }
        }
    })
}

/// Python wrapper for DNS reverse lookup
#[cfg(feature = "python")]
#[pyfunction]
#[must_use]
fn dns_reverse(py: Python, ip: String) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        use hickory_resolver::config::*;
        use hickory_resolver::TokioAsyncResolver;

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        match ip.parse::<IpAddr>() {
            Ok(ip_addr) => {
                match resolver.reverse_lookup(ip_addr).await {
                    Ok(response) => {
                        let names: Vec<String> = response.iter().map(|n| n.to_string()).collect();
                        Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                            let result = PyDict::new(py);
                            result.set_item("ip", ip)?;
                            result.set_item("names", names)?;
                            result.set_item("success", true)?;
                            Ok(result.into())
                        })
                    }
                    Err(e) => {
                        Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                            let result = PyDict::new(py);
                            result.set_item("ip", ip)?;
                            result.set_item("error", e.to_string())?;
                            result.set_item("success", false)?;
                            Ok(result.into())
                        })
                    }
                }
            }
            Err(e) => {
                Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let result = PyDict::new(py);
                    result.set_item("ip", ip)?;
                    result.set_item("error", format!("Invalid IP: {}", e))?;
                    result.set_item("success", false)?;
                    Ok(result.into())
                })
            }
        }
    })
}

/// Python wrapper for dig operation
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (domain, record_type="A".to_string(), nameserver=None, short=false))]
#[must_use]
fn dig_query(
    py: Python,
    domain: String,
    record_type: String,
    nameserver: Option<String>,
    short: bool,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let ns_ip = if let Some(ns_str) = nameserver {
            ns_str.parse::<IpAddr>().ok()
        } else {
            None
        };

        let rec_type = match dig::parse_record_type(&record_type) {
            Some(rt) => rt,
            None => {
                return Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let result = PyDict::new(py);
                    result.set_item("domain", domain)?;
                    result.set_item("error", format!("Invalid record type: {}", record_type))?;
                    result.set_item("success", false)?;
                    Ok(result.into())
                });
            }
        };

        let options = dig::DigOptions {
            query_type: rec_type,
            nameserver: ns_ip,
            show_stats: true,
            trace: false,
            short,
        };

        match dig::dig(&domain, options).await {
            Ok(result) => {
                Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let py_result = PyDict::new(py);
                    py_result.set_item("domain", result.domain)?;
                    py_result.set_item("query_type", result.query_type.to_string())?;
                    py_result.set_item("answers", result.answers)?;
                    py_result.set_item("authorities", result.authorities)?;
                    py_result.set_item("additionals", result.additionals)?;
                    py_result.set_item("query_time", result.query_time)?;
                    py_result.set_item("server", result.server)?;
                    py_result.set_item("status", result.status)?;
                    py_result.set_item("success", true)?;
                    Ok(py_result.into())
                })
            }
            Err(e) => {
                Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let result = PyDict::new(py);
                    result.set_item("domain", domain)?;
                    result.set_item("error", e)?;
                    result.set_item("success", false)?;
                    Ok(result.into())
                })
            }
        }
    })
}

/// Python wrapper for HTTP GET operation
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (url, timeout=10))]
#[must_use]
fn http_get(py: Python, url: String, timeout: u64) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        use std::time::Duration;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))
            .unwrap_or_else(|e| {
                panic!("Critical: HTTP client build failed: {}", e);
            });

        let url_formatted = if !url.starts_with("http://") && !url.starts_with("https://") {
            format!("http://{}", url)
        } else {
            url.to_string()
        };

        let start = std::time::Instant::now();

        match client.get(&url_formatted).send().await {
            Ok(response) => {
                let duration = start.elapsed();
                let status = response.status().as_u16();
                let content_length = response.content_length().unwrap_or(0);

                Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let result = PyDict::new(py);
                    result.set_item("url", url_formatted)?;
                    result.set_item("status", status)?;
                    result.set_item("content_length", content_length)?;
                    result.set_item("duration_ms", duration.as_millis() as u64)?;
                    result.set_item("success", true)?;
                    Ok(result.into())
                })
            }
            Err(e) => {
                let duration = start.elapsed();
                Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let result = PyDict::new(py);
                    result.set_item("url", url_formatted)?;
                    result.set_item("error", e.to_string())?;
                    result.set_item("duration_ms", duration.as_millis() as u64)?;
                    result.set_item("success", false)?;
                    Ok(result.into())
                })
            }
        }
    })
}

/// Python wrapper for port scanning
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (host, ports, timeout=2, max_concurrent=1000))]
#[must_use]
fn port_scan(
    py: Python,
    host: String,
    ports: Vec<u16>,
    timeout: u64,
    max_concurrent: usize,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        use std::time::Duration;
        use tokio::net::TcpStream;
        use tokio::time::timeout as tokio_timeout;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let start = std::time::Instant::now();
        let host = Arc::new(host);
        let total_ports = ports.len();

        // Prevent excessive memory allocation
        const MAX_TASKS: usize = 10000;
        if total_ports > MAX_TASKS {
            return Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                let result = PyDict::new(py);
                result.set_item("error", format!("Too many ports: {} (max: {})", total_ports, MAX_TASKS))?;
                result.set_item("success", false)?;
                Ok(result.into())
            });
        }

        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
        let mut tasks = Vec::with_capacity(total_ports.min(1000));

        for port in ports {
            let host = Arc::clone(&host);
            let semaphore = Arc::clone(&semaphore);

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.ok()?;
                let addr = format!("{}:{}", host, port);

                match tokio_timeout(
                    Duration::from_secs(timeout),
                    TcpStream::connect(&addr)
                ).await {
                    Ok(Ok(stream)) => {
                        drop(stream);
                        Some((port, true))
                    }
                    Ok(Err(_)) | Err(_) => Some((port, false)),
                }
            });

            tasks.push(task);
        }

        let mut open_ports = Vec::new();
        let closed_count = Arc::new(AtomicUsize::new(0));

        for task in tasks {
            if let Ok(Some((port, is_open))) = task.await {
                if is_open {
                    open_ports.push(port);
                } else {
                    closed_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        open_ports.sort_unstable();
        let duration = start.elapsed();
        let closed = closed_count.load(Ordering::Relaxed);

        Python::with_gil(|py| -> PyResult<Py<PyAny>> {
            let result = PyDict::new(py);
            result.set_item("host", host.as_ref())?;
            result.set_item("open_ports", open_ports)?;
            result.set_item("closed_ports", closed)?;
            result.set_item("total_ports", total_ports)?;
            result.set_item("duration_ms", duration.as_millis() as u64)?;
            result.set_item("success", true)?;
            Ok(result.into())
        })
    })
}

// Fuzzing functions
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (base_url, wordlist, max_concurrent=50, timeout=10, status_filter=None, show_errors=false))]
fn fuzz_directories(
    py: Python,
    base_url: String,
    wordlist: Vec<String>,
    max_concurrent: usize,
    timeout: u64,
    status_filter: Option<Vec<u16>>,
    show_errors: bool,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let options = fuzz::FuzzOptions {
            timeout_secs: timeout,
            max_concurrent,
            status_filter,
            show_errors,
            ..Default::default()
        };

        let results = fuzz::fuzz_directories(&base_url, wordlist, options).await;

        Python::with_gil(|py| -> PyResult<Py<PyAny>> {
            let py_results = PyList::empty(py);

            for result in results {
                let py_result = PyDict::new(py);
                py_result.set_item("url", result.url)?;
                py_result.set_item("status_code", result.status_code)?;
                py_result.set_item("content_length", result.content_length)?;
                py_result.set_item("duration_ms", result.duration_ms)?;
                py_result.set_item("found", result.found)?;
                if let Some(err) = result.error {
                    py_result.set_item("error", err)?;
                }
                py_results.append(py_result)?;
            }

            Ok(py_results.into())
        })
    })
}

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (domain, wordlist, max_concurrent=50, timeout=10, show_errors=false))]
fn fuzz_subdomains(
    py: Python,
    domain: String,
    wordlist: Vec<String>,
    max_concurrent: usize,
    timeout: u64,
    show_errors: bool,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let options = fuzz::FuzzOptions {
            timeout_secs: timeout,
            max_concurrent,
            show_errors,
            ..Default::default()
        };

        let results = fuzz::fuzz_subdomains(&domain, wordlist, options).await;

        Python::with_gil(|py| -> PyResult<Py<PyAny>> {
            let py_results = PyList::empty(py);

            for result in results {
                let py_result = PyDict::new(py);
                py_result.set_item("url", result.url)?;
                py_result.set_item("status_code", result.status_code)?;
                py_result.set_item("content_length", result.content_length)?;
                py_result.set_item("duration_ms", result.duration_ms)?;
                py_result.set_item("found", result.found)?;
                if let Some(err) = result.error {
                    py_result.set_item("error", err)?;
                }
                py_results.append(py_result)?;
            }

            Ok(py_results.into())
        })
    })
}

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (base_url, params, payloads, max_concurrent=50, timeout=10, show_errors=false))]
fn fuzz_parameters(
    py: Python,
    base_url: String,
    params: Vec<String>,
    payloads: Vec<String>,
    max_concurrent: usize,
    timeout: u64,
    show_errors: bool,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let options = fuzz::FuzzOptions {
            timeout_secs: timeout,
            max_concurrent,
            show_errors,
            ..Default::default()
        };

        let results = fuzz::fuzz_parameters(&base_url, params, payloads, options).await;

        Python::with_gil(|py| -> PyResult<Py<PyAny>> {
            let py_results = PyList::empty(py);

            for result in results {
                let py_result = PyDict::new(py);
                py_result.set_item("url", result.url)?;
                py_result.set_item("status_code", result.status_code)?;
                py_result.set_item("content_length", result.content_length)?;
                py_result.set_item("duration_ms", result.duration_ms)?;
                py_result.set_item("found", result.found)?;
                if let Some(err) = result.error {
                    py_result.set_item("error", err)?;
                }
                py_results.append(py_result)?;
            }

            Ok(py_results.into())
        })
    })
}

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (url, payloads, max_concurrent=50, timeout=10, show_errors=false))]
fn fuzz_parameter_values(
    py: Python,
    url: String,
    payloads: Vec<String>,
    max_concurrent: usize,
    timeout: u64,
    show_errors: bool,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let options = fuzz::FuzzOptions {
            timeout_secs: timeout,
            max_concurrent,
            show_errors,
            ..Default::default()
        };

        let results = fuzz::fuzz_parameter_values(&url, payloads, options).await;

        Python::with_gil(|py| -> PyResult<Py<PyAny>> {
            let py_results = PyList::empty(py);

            for result in results {
                let py_result = PyDict::new(py);
                py_result.set_item("url", result.url)?;
                py_result.set_item("status_code", result.status_code)?;
                py_result.set_item("content_length", result.content_length)?;
                py_result.set_item("duration_ms", result.duration_ms)?;
                py_result.set_item("found", result.found)?;
                if let Some(err) = result.error {
                    py_result.set_item("error", err)?;
                }
                py_results.append(py_result)?;
            }

            Ok(py_results.into())
        })
    })
}

// Wordlist functions
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (path=None))]
fn load_wordlist(path: Option<String>) -> PyResult<Vec<String>> {
    match fuzz::load_wordlist(path.as_deref()) {
        Ok(wordlist) => Ok(wordlist),
        Err(e) => Err(pyo3::exceptions::PyIOError::new_err(format!(
            "Failed to load wordlist: {}",
            e
        ))),
    }
}

#[cfg(feature = "python")]
#[pyfunction]
fn get_common_file_extensions() -> PyResult<Vec<String>> {
    Ok(fuzz::get_common_file_extensions()
        .iter()
        .map(|s| (*s).to_string())
        .collect())
}

#[cfg(feature = "python")]
#[pyfunction]
fn get_backup_file_patterns() -> PyResult<Vec<String>> {
    Ok(fuzz::get_backup_file_patterns())
}

#[cfg(feature = "python")]
#[pyfunction]
fn get_common_parameters() -> PyResult<Vec<String>> {
    Ok(fuzz::get_common_parameters())
}

#[cfg(feature = "python")]
#[pyfunction]
fn get_common_payloads() -> PyResult<Vec<String>> {
    Ok(fuzz::get_common_payloads())
}

#[cfg(feature = "python")]
#[pyfunction]
fn generate_wordlist_with_extensions(
    base_words: Vec<String>,
    extensions: Vec<String>,
) -> PyResult<Vec<String>> {
    let ext_refs: Vec<&str> = extensions.iter().map(|s| s.as_str()).collect();
    Ok(fuzz::generate_wordlist_with_extensions(base_words, ext_refs))
}

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (base_words, extensions, max_depth=2))]
fn generate_permutations(
    base_words: Vec<String>,
    extensions: Vec<String>,
    max_depth: usize,
) -> PyResult<Vec<String>> {
    let ext_refs: Vec<&str> = extensions.iter().map(|s| s.as_str()).collect();
    Ok(fuzz::generate_permutations(base_words, ext_refs, max_depth))
}

#[cfg(feature = "python")]
#[pyfunction]
fn combine_words(
    words: Vec<String>,
    separators: Vec<String>,
) -> PyResult<Vec<String>> {
    let sep_refs: Vec<&str> = separators.iter().map(|s| s.as_str()).collect();
    Ok(fuzz::combine_words(words, sep_refs))
}

#[cfg(feature = "python")]
#[pyfunction]
fn generate_case_variations(word: String) -> PyResult<Vec<String>> {
    Ok(fuzz::generate_case_variations(&word))
}

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (base_words, start=1, end=10))]
fn generate_numbered_variations(
    base_words: Vec<String>,
    start: usize,
    end: usize,
) -> PyResult<Vec<String>> {
    Ok(fuzz::generate_numbered_variations(base_words, start, end))
}

/// Python module definition
#[cfg(feature = "python")]
#[pymodule]
fn netool(_py: Python, m: &PyModule) -> PyResult<()> {
    // DNS functions
    m.add_function(wrap_pyfunction!(dns_resolve, m)?)?;
    m.add_function(wrap_pyfunction!(dns_reverse, m)?)?;
    m.add_function(wrap_pyfunction!(dig_query, m)?)?;

    // HTTP functions
    m.add_function(wrap_pyfunction!(http_get, m)?)?;
    m.add_function(wrap_pyfunction!(port_scan, m)?)?;

    // Fuzzing functions
    m.add_function(wrap_pyfunction!(fuzz_directories, m)?)?;
    m.add_function(wrap_pyfunction!(fuzz_subdomains, m)?)?;
    m.add_function(wrap_pyfunction!(fuzz_parameters, m)?)?;
    m.add_function(wrap_pyfunction!(fuzz_parameter_values, m)?)?;

    // Wordlist functions
    m.add_function(wrap_pyfunction!(load_wordlist, m)?)?;
    m.add_function(wrap_pyfunction!(get_common_file_extensions, m)?)?;
    m.add_function(wrap_pyfunction!(get_backup_file_patterns, m)?)?;
    m.add_function(wrap_pyfunction!(get_common_parameters, m)?)?;
    m.add_function(wrap_pyfunction!(get_common_payloads, m)?)?;

    // Generator functions
    m.add_function(wrap_pyfunction!(generate_wordlist_with_extensions, m)?)?;
    m.add_function(wrap_pyfunction!(generate_permutations, m)?)?;
    m.add_function(wrap_pyfunction!(combine_words, m)?)?;
    m.add_function(wrap_pyfunction!(generate_case_variations, m)?)?;
    m.add_function(wrap_pyfunction!(generate_numbered_variations, m)?)?;

    // SQL injection scanner
    m.add_function(wrap_pyfunction!(sqli_scan, m)?)?;

    Ok(())
}