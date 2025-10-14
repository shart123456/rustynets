use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::net::IpAddr;

mod dig;
mod http;
mod fuzz;

/// Python wrapper for DNS resolve operation
#[pyfunction]
fn dns_resolve(py: Python, domain: String) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::TokioAsyncResolver;

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
#[pyfunction]
fn dns_reverse(py: Python, ip: String) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::TokioAsyncResolver;

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
#[pyfunction]
#[pyo3(signature = (domain, record_type="A".to_string(), nameserver=None, short=false))]
fn dig_query(
    py: Python,
    domain: String,
    record_type: String,
    nameserver: Option<String>,
    short: bool,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let ns_ip = if let Some(ns_str) = nameserver {
            match ns_str.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => None,
            }
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
#[pyfunction]
#[pyo3(signature = (url, timeout=10))]
fn http_get(py: Python, url: String, timeout: u64) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        use std::time::Duration;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .build()
            .expect("Failed to create HTTP client");

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

/// Python wrapper for port scanning (nmap-like)
#[pyfunction]
#[pyo3(signature = (host, ports, timeout=2, max_concurrent=1000))]
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

        let start = std::time::Instant::now();
        let host = Arc::new(host);
        let total_ports = ports.len();

        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
        let mut tasks = Vec::with_capacity(total_ports);

        for port in ports {
            let host = Arc::clone(&host);
            let semaphore = Arc::clone(&semaphore);

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.ok()?;
                let addr = format!("{}:{}", host, port);

                let result = match tokio_timeout(
                    Duration::from_secs(timeout),
                    TcpStream::connect(&addr)
                ).await {
                    Ok(Ok(stream)) => {
                        drop(stream);
                        Python::with_gil(|py| {
                            if let Ok(print) = py.import("builtins").and_then(|m| m.getattr("print")) {
                                let _ = print.call1((format!("[+] Open port found: {}:{}", host, port),));
                            }
                        });
                        Some((port, true))
                    }
                    Ok(Err(_)) => Some((port, false)),
                    Err(_) => Some((port, false)),
                };

                result
            });

            tasks.push(task);
        }

        let mut open_ports = Vec::new();
        let closed_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        for task in tasks {
            match task.await {
                Ok(Some((port, is_open))) => {
                    if is_open {
                        open_ports.push(port);
                    } else {
                        closed_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                _ => {}
            }
        }

        open_ports.sort_unstable();
        let duration = start.elapsed();
        let closed = closed_count.load(std::sync::atomic::Ordering::Relaxed);

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

/// Python wrapper for secure HTTP GET with vulnerability analysis
#[pyfunction]
#[pyo3(signature = (url, follow_redirects=true, max_redirects=10, timeout=30, analyze_security=true))]
fn http_get_secure(
    py: Python,
    url: String,
    follow_redirects: bool,
    max_redirects: usize,
    timeout: u64,
    analyze_security: bool,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let options = http::HttpOptions {
            follow_redirects,
            max_redirects,
            timeout_secs: timeout,
            user_agent: "Mozilla/5.0 (Security Scanner)".to_string(),
            analyze_security,
        };

        match http::http_get_secure(&url, options).await {
            Ok(result) => {
                Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let py_result = PyDict::new(py);
                    py_result.set_item("url", result.url)?;
                    py_result.set_item("final_url", result.final_url)?;
                    py_result.set_item("status", result.status_code)?;
                    py_result.set_item("content_length", result.content_length)?;
                    py_result.set_item("duration_ms", result.duration_ms)?;
                    py_result.set_item("redirected", result.redirected)?;

                    let py_headers = PyDict::new(py);
                    for (k, v) in &result.headers {
                        py_headers.set_item(k, v)?;
                    }
                    py_result.set_item("headers", py_headers)?;

                    if let Some(sec) = result.security_analysis {
                        let security_dict = PyDict::new(py);
                        security_dict.set_item("risk_score", sec.risk_score)?;
                        security_dict.set_item("missing_headers", sec.missing_headers)?;
                        security_dict.set_item("insecure_headers", sec.insecure_headers)?;
                        security_dict.set_item("vulnerabilities", sec.vulnerabilities)?;
                        py_result.set_item("security_analysis", security_dict)?;
                    }

                    py_result.set_item("success", true)?;
                    Ok(py_result.into())
                })
            }
            Err(e) => {
                Python::with_gil(|py| -> PyResult<Py<PyAny>> {
                    let result = PyDict::new(py);
                    result.set_item("url", url)?;
                    result.set_item("error", e)?;
                    result.set_item("success", false)?;
                    Ok(result.into())
                })
            }
        }
    })
}

/// Python wrapper for directory fuzzing
#[pyfunction]
#[pyo3(signature = (base_url, wordlist, max_concurrent=50, timeout=10, status_filter=None))]
fn fuzz_directories(
    py: Python,
    base_url: String,
    wordlist: Vec<String>,
    max_concurrent: usize,
    timeout: u64,
    status_filter: Option<Vec<u16>>,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let options = fuzz::FuzzOptions {
            timeout_secs: timeout,
            max_concurrent,
            status_filter,
            ..Default::default()
        };

        let results = fuzz::fuzz_directories(&base_url, wordlist, options).await;

        Python::with_gil(|py| -> PyResult<Py<PyAny>> {
            let py_results = pyo3::types::PyList::empty(py);

            for result in results {
                let py_result = PyDict::new(py);
                py_result.set_item("url", result.url)?;
                py_result.set_item("status", result.status_code)?;
                py_result.set_item("content_length", result.content_length)?;
                py_result.set_item("duration_ms", result.duration_ms)?;
                py_result.set_item("found", result.found)?;
                py_results.append(py_result)?;
            }

            Ok(py_results.into())
        })
    })
}

/// Python wrapper for subdomain fuzzing
#[pyfunction]
#[pyo3(signature = (domain, wordlist, max_concurrent=50, timeout=10))]
fn fuzz_subdomains(
    py: Python,
    domain: String,
    wordlist: Vec<String>,
    max_concurrent: usize,
    timeout: u64,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let options = fuzz::FuzzOptions {
            timeout_secs: timeout,
            max_concurrent,
            ..Default::default()
        };

        let results = fuzz::fuzz_subdomains(&domain, wordlist, options).await;

        Python::with_gil(|py| -> PyResult<Py<PyAny>> {
            let py_results = pyo3::types::PyList::empty(py);

            for result in results {
                let py_result = PyDict::new(py);
                py_result.set_item("url", result.url)?;
                py_result.set_item("status", result.status_code)?;
                py_result.set_item("content_length", result.content_length)?;
                py_result.set_item("duration_ms", result.duration_ms)?;
                py_result.set_item("found", result.found)?;
                py_results.append(py_result)?;
            }

            Ok(py_results.into())
        })
    })
}

/// Load wordlist from file
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

/// Python module definition
#[pymodule]
fn netool(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(dns_resolve, m)?)?;
    m.add_function(wrap_pyfunction!(dns_reverse, m)?)?;
    m.add_function(wrap_pyfunction!(dig_query, m)?)?;
    m.add_function(wrap_pyfunction!(http_get, m)?)?;
    m.add_function(wrap_pyfunction!(port_scan, m)?)?;
    m.add_function(wrap_pyfunction!(http_get_secure, m)?)?;
    m.add_function(wrap_pyfunction!(fuzz_directories, m)?)?;
    m.add_function(wrap_pyfunction!(fuzz_subdomains, m)?)?;
    m.add_function(wrap_pyfunction!(load_wordlist, m)?)?;
    Ok(())
}