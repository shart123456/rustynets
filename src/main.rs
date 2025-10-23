use clap::{Parser, Subcommand};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;

mod dig;
mod fuzz;
mod sqli;
mod bruteforce;
mod xss;

use bruteforce::{BruteForcer, BruteForceConfig, HttpMethod, DetectionMode};

#[derive(Parser)]
#[command(name = "netool")]
#[command(version = "2.0.0")]
#[command(about = "Comprehensive network operations and security testing tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform DNS operations
    #[command(arg_required_else_help = true)]
    Dns {
        /// Operation to perform
        #[arg(short, long, value_parser = ["resolve", "reverse"])]
        operation: String,

        /// Target: single IP/domain or path to file
        #[arg(short, long)]
        target: String,
    },

    /// Perform ping operations
    Ping {
        /// Target: single IP or path to file
        #[arg(short, long)]
        target: String,

        /// Number of ping attempts
        #[arg(short, long, default_value = "4")]
        count: u32,
    },

    /// Perform HTTP GET requests
    Get {
        /// Target: single URL or path to file
        #[arg(short, long)]
        target: String,

        /// Request timeout in seconds
        #[arg(short = 'o', long, default_value = "10")]
        timeout: u64,
    },

    /// Perform detailed DNS dig operations
    Dig {
        /// Domain to query
        #[arg(short, long)]
        domain: String,

        /// Record type (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA, ANY)
        #[arg(short = 'r', long, default_value = "A")]
        record_type: String,

        /// Custom nameserver IP
        #[arg(short = 'n', long)]
        nameserver: Option<IpAddr>,

        /// Short output format (answers only)
        #[arg(short, long)]
        short: bool,

        /// Query all common record types
        #[arg(short, long)]
        all: bool,
    },

    /// Web fuzzing operations
    Fuzz {
        /// Target URL or domain
        #[arg(short, long)]
        url: String,

        /// Wordlist file path (optional, uses built-in if not provided)
        #[arg(short, long)]
        wordlist: Option<String>,

        /// Fuzzing mode: dir, subdomain, param, extensions
        #[arg(short, long, default_value = "dir")]
        mode: String,

        /// Concurrent workers
        #[arg(short, long, default_value = "50")]
        concurrent: usize,

        /// Filter by status codes (comma-separated, e.g., "200,301,403")
        #[arg(short = 's', long)]
        status_filter: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 't', long, default_value = "10")]
        timeout: u64,

        /// Enable recursive fuzzing
        #[arg(short, long)]
        recursive: bool,

        /// Maximum recursion depth
        #[arg(long, default_value = "3")]
        max_depth: usize,

        /// File extensions (comma-separated, e.g., ".php,.bak,.old")
        #[arg(short, long)]
        extensions: Option<String>,

        /// Enable baseline detection (custom 404 detection)
        #[arg(long, default_value = "true")]
        baseline: bool,
    },

    /// Brute force login attacks (AUTHORIZED USE ONLY)
    #[command(name = "bruteforce")]
    Bruteforce {
        /// Detection mode: length (default), text, or status
        #[arg(long, default_value = "length")]
        detection: String,

        /// Target URL (e.g., http://127.0.0.1/vulnerabilities/brute/)
        #[arg(short, long)]
        url: String,

        /// Path to usernames file
        #[arg(short = 'U', long)]
        usernames: String,

        /// Path to passwords file
        #[arg(short = 'P', long)]
        passwords: String,

        /// Number of concurrent workers
        #[arg(short, long, default_value = "50")]
        workers: usize,

        /// Request delay in milliseconds
        #[arg(short, long, default_value = "0")]
        delay: u64,

        /// HTTP method (GET or POST)
        #[arg(short, long, default_value = "GET")]
        method: String,

        /// Success indicator text
        #[arg(long, default_value = "Welcome to the password protected area")]
        success_text: String,

        /// Failure indicator text
        #[arg(long, default_value = "Username and/or password incorrect")]
        failure_text: String,

        /// Cookie string for authentication
        #[arg(long)]
        cookies: Option<String>,
    },

    /// XSS vulnerability scanner (AUTHORIZED USE ONLY)
    #[command(name = "xss-scan")]
    XssScan {
        /// Target URL to scan
        #[arg(short, long)]
        target: String,

        /// Confirm you are authorized to test this target
        #[arg(long)]
        confirm_authorized: bool,

        /// Maximum concurrent requests
        #[arg(long, default_value = "10")]
        max_concurrency: usize,

        /// Request timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,

        /// Cookie string for authentication
        #[arg(long)]
        cookies: Option<String>,

        /// Test for reflected XSS
        #[arg(long, default_value = "true")]
        test_reflected: bool,

        /// Test for stored XSS
        #[arg(long, default_value = "false")]
        test_stored: bool,

        /// Test for DOM-based XSS
        #[arg(long, default_value = "false")]
        test_dom: bool,

        /// Output format: json, yaml, or text
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Output file path
        #[arg(long)]
        output_file: Option<std::path::PathBuf>,
    },

    /// SQL injection vulnerability scanner (AUTHORIZED USE ONLY)
    #[command(name = "sqli-scan")]
    SqliScan {
        /// Target URL to scan
        #[arg(short, long)]
        target: String,

        /// Confirm you are authorized to test this target
        #[arg(long)]
        confirm_authorized: bool,

        /// Authorization token or proof of permission
        #[arg(long)]
        auth_token: Option<String>,

        /// Maximum concurrent requests (default: 5, max: 20)
        #[arg(long, default_value = "5")]
        max_concurrency: usize,

        /// Maximum requests per second (default: 10, max: 50)
        #[arg(long, default_value = "10")]
        rps: u32,

        /// Request timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,

        /// Maximum crawl depth
        #[arg(long, default_value = "3")]
        max_depth: usize,

        /// Enable out-of-band (DNS/HTTP callback) testing
        #[arg(long)]
        enable_oob: bool,

        /// OOB callback host (required if --enable-oob is set)
        #[arg(long)]
        oob_host: Option<String>,

        /// Time delay for time-based tests in seconds (max 5)
        #[arg(long, default_value = "3")]
        time_delay: u64,

        /// Number of samples for time-based statistical validation
        #[arg(long, default_value = "5")]
        time_samples: usize,

        /// Payload configuration file (YAML with test payloads)
        #[arg(long)]
        payload_file: Option<PathBuf>,

        /// Output format: json, yaml, or text
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Output file path (if not specified, writes to stdout)
        #[arg(long)]
        output_file: Option<PathBuf>,

        /// Short/concise output mode
        #[arg(long)]
        short: bool,

        /// Dry run - validate config without sending requests
        #[arg(long)]
        dry_run: bool,

        /// Custom User-Agent string
        #[arg(long)]
        user_agent: Option<String>,

        /// Additional headers in key:value format
        #[arg(long)]
        headers: Vec<String>,

        /// Cookie string
        #[arg(long)]
        cookies: Option<String>,

        /// Maximum number of endpoints to test (0 = unlimited)
        #[arg(long, default_value = "100")]
        max_endpoints: usize,
    },
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Setup graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                eprintln!("\nReceived shutdown signal, cleaning up...");
                let _ = shutdown_tx.send(());
            }
            Err(e) => {
                eprintln!("Error setting up signal handler: {}", e);
            }
        }
    });

    let cli = Cli::parse();

    tokio::select! {
        _ = run_command(cli) => {},
        _ = &mut shutdown_rx => {
            eprintln!("Shutting down gracefully");
        }
    }
}

async fn run_command(cli: Cli) {
    match cli.command {
        Commands::Dns { operation, target } => {
            handle_dns(operation, target).await;
        }
        Commands::Ping { target, count } => {
            handle_ping(target, count).await;
        }
        Commands::Get { target, timeout: timeout_secs } => {
            handle_get(target, timeout_secs).await;
        }
        Commands::Dig { domain, record_type, nameserver, short, all } => {
            handle_dig(domain, record_type, nameserver, short, all).await;
        }
        Commands::Fuzz {
            url,
            wordlist,
            mode,
            concurrent,
            status_filter,
            timeout,
            recursive,
            max_depth,
            extensions,
            baseline,
        } => {
            handle_fuzz(
                url,
                wordlist,
                mode,
                concurrent,
                status_filter,
                timeout,
                recursive,
                max_depth,
                extensions,
                baseline,
            ).await;
        }
        Commands::Bruteforce {
            url,
            usernames,
            passwords,
            workers,
            delay,
            method,
            success_text,
            failure_text,
            cookies,
            detection,
        } => {
            handle_bruteforce(
                url,
                usernames,
                passwords,
                workers,
                delay,
                method,
                detection,
                Some(success_text),
                Some(failure_text),
                cookies,
            )
                .await;
        }
        Commands::XssScan {
            target,
            confirm_authorized,
            max_concurrency,
            timeout,
            cookies,
            test_reflected,
            test_stored,
            test_dom,
            output,
            output_file,
        } => {
            handle_xss_scan(
                target,
                confirm_authorized,
                max_concurrency,
                timeout,
                cookies,
                test_reflected,
                test_stored,
                test_dom,
                output,
                output_file,
            )
                .await;
        }
        Commands::SqliScan {
            target,
            confirm_authorized,
            auth_token,
            max_concurrency,
            rps,
            timeout,
            max_depth,
            enable_oob,
            oob_host,
            time_delay,
            time_samples,
            payload_file,
            output,
            output_file,
            short,
            dry_run,
            user_agent,
            headers,
            cookies,
            max_endpoints,
        } => {
            handle_sqli_scan(
                target,
                confirm_authorized,
                auth_token,
                max_concurrency,
                rps,
                timeout,
                max_depth,
                enable_oob,
                oob_host,
                time_delay,
                time_samples,
                payload_file,
                output,
                output_file,
                short,
                dry_run,
                user_agent,
                headers,
                cookies,
                max_endpoints,
            )
                .await;
        }
    }
}

// ============================================================================
// BRUTE FORCE HANDLER
// ============================================================================

#[allow(clippy::too_many_arguments)]
async fn handle_bruteforce(
    url: String,
    usernames_file: String,
    passwords_file: String,
    workers: usize,
    delay: u64,
    method: String,
    detection: String,
    success_text: Option<String>,
    failure_text: Option<String>,
    cookies: Option<String>,
) {
    println!("\n{}", "═".repeat(70));
    println!("  BRUTE FORCE LOGIN ATTACK - AUTHORIZED USE ONLY");
    println!("{}", "═".repeat(70));
    println!("⚠️  WARNING: Use only on systems you own or have permission to test");
    println!("   Unauthorized access attempts are illegal.");
    println!("{}\n", "═".repeat(70));

    println!("[*] Target: {}", url);
    println!("[*] Workers: {}", workers);
    println!("[*] Method: {}", method);
    if delay > 0 {
        println!("[*] Delay: {}ms between requests", delay);
    }

    let http_method = match method.to_uppercase().as_str() {
        "POST" => HttpMethod::POST,
        _ => HttpMethod::GET,
    };

    let detection_mode = match detection.as_str() {
        "text" => {
            let success = success_text.unwrap_or_else(|| {
                eprintln!("Error: --success-text required for text detection mode");
                std::process::exit(1);
            });
            let failure = failure_text.unwrap_or_else(|| {
                eprintln!("Error: --failure-text required for text detection mode");
                std::process::exit(1);
            });
            DetectionMode::TextBased {
                success_indicator: success,
                failure_indicator: failure,
            }
        }
        "status" => DetectionMode::StatusCode {
            success_codes: vec![200, 302],
            failure_codes: vec![401, 403],
        },
        _ => DetectionMode::LengthBased {
            baseline_length: None,
            variance_threshold: 50,
        },
    };

    let config = BruteForceConfig {
        target_url: url,
        concurrent_requests: workers,
        delay_ms: delay,
        method: http_method,
        detection_mode,
        ..Default::default()
    };

    // Handle cookies if provided
    let cookie_jar = if let Some(cookie_str) = cookies {
        use reqwest::cookie::Jar;
        use std::sync::Arc;
        use url::Url;

        let jar = Jar::default();
        if let Ok(url) = Url::parse(&config.target_url) {
            jar.add_cookie_str(&cookie_str, &url);
        }
        Some(Arc::new(jar))
    } else {
        None
    };

    let bruteforcer = BruteForcer::new(config, cookie_jar);

    println!("\n[*] Loading credentials...");
    let usernames = match BruteForcer::load_usernames(&usernames_file).await {
        Ok(u) => {
            println!("[+] Loaded {} usernames", u.len());
            u
        }
        Err(e) => {
            eprintln!("[-] Failed to load usernames from '{}': {}", usernames_file, e);
            return;
        }
    };

    let passwords = match BruteForcer::load_passwords(&passwords_file).await {
        Ok(p) => {
            println!("[+] Loaded {} passwords", p.len());
            p
        }
        Err(e) => {
            eprintln!("[-] Failed to load passwords from '{}': {}", passwords_file, e);
            return;
        }
    };

    let _result = bruteforcer.attack(usernames, passwords).await;
}

// ============================================================================
// XSS SCANNER HANDLER
// ============================================================================

async fn handle_xss_scan(
    target: String,
    confirm_authorized: bool,
    max_concurrency: usize,
    timeout: u64,
    cookies: Option<String>,
    test_reflected: bool,
    test_stored: bool,
    test_dom: bool,
    output_format: String,
    output_file: Option<std::path::PathBuf>,
) {
    if !confirm_authorized {
        eprintln!("\n{}", "═".repeat(70));
        eprintln!("  ⛔ AUTHORIZATION REQUIRED");
        eprintln!("{}", "═".repeat(70));
        eprintln!("This XSS scanner is for AUTHORIZED security testing ONLY.");
        eprintln!("\nYou must provide:");
        eprintln!("  --confirm-authorized  (acknowledges you have permission)");
        eprintln!("\n⚖️  LEGAL WARNING:");
        eprintln!("   Using this tool without authorization is ILLEGAL.");
        eprintln!("{}", "═".repeat(70));
        std::process::exit(1);
    }

    let config = xss::XssConfig {
        target,
        max_concurrency,
        timeout_secs: timeout,
        cookies,
        test_reflected,
        test_stored,
        test_dom,
        ..Default::default()
    };

    let scanner = xss::XssScanner::new(config);

    match scanner.scan().await {
        Ok(results) => {
            match output_format.as_str() {
                "json" => {
                    let json = serde_json::to_string_pretty(&results).unwrap();
                    if let Some(path) = output_file {
                        std::fs::write(&path, json).unwrap();
                        println!("✓ Results saved to: {}", path.display());
                    } else {
                        println!("{}", json);
                    }
                }
                "yaml" => {
                    let yaml = serde_yaml::to_string(&results).unwrap();
                    if let Some(path) = output_file {
                        std::fs::write(&path, yaml).unwrap();
                        println!("✓ Results saved to: {}", path.display());
                    } else {
                        println!("{}", yaml);
                    }
                }
                _ => {
                    xss::print_results(&results);

                    if let Some(path) = output_file {
                        let text = format!("XSS Scan Results\nTarget: {}\nVulnerabilities: {}\n",
                                           results.target, results.vulnerabilities.len());
                        std::fs::write(&path, text).unwrap();
                        println!("\n✓ Results also saved to: {}", path.display());
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("\n⛔ Scan failed: {}", e);
            std::process::exit(1);
        }
    }
}

// ============================================================================
// SQL INJECTION SCANNER HANDLER
// ============================================================================

#[allow(clippy::too_many_arguments)]
async fn handle_sqli_scan(
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
    time_samples: usize,
    payload_file: Option<PathBuf>,
    output_format: String,
    output_file: Option<PathBuf>,
    short: bool,
    dry_run: bool,
    user_agent: Option<String>,
    headers: Vec<String>,
    cookies: Option<String>,
    max_endpoints: usize,
) {
    // CRITICAL SAFETY CHECK: Require explicit authorization
    if !confirm_authorized && auth_token.is_none() {
        eprintln!("\n{}", "═".repeat(70));
        eprintln!("  ⛔ AUTHORIZATION REQUIRED");
        eprintln!("{}", "═".repeat(70));
        eprintln!("This SQL injection scanner is for AUTHORIZED security testing ONLY.");
        eprintln!("\nYou must provide either:");
        eprintln!("  --confirm-authorized  (acknowledges you have permission)");
        eprintln!("  --auth-token <token>  (authorization token/proof)");
        eprintln!("\n⚖️  LEGAL WARNING:");
        eprintln!("   Using this tool without authorization is ILLEGAL and may result");
        eprintln!("   in criminal prosecution under computer fraud and abuse laws.");
        eprintln!("\n   Only test systems you own or have explicit written permission");
        eprintln!("   to assess.");
        eprintln!("\n{}", "═".repeat(70));
        eprintln!("Exiting for your safety.\n");
        std::process::exit(1);
    }

    // Display safety banner
    print_sqli_safety_banner(enable_oob, rps, max_concurrency, time_delay);

    // Parse custom headers
    let mut custom_headers = std::collections::HashMap::new();
    for header in headers {
        if let Some((k, v)) = header.split_once(':') {
            custom_headers.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    // Load payload configuration
    let payload_config = if let Some(ref path) = payload_file {
        match sqli::config::SqliConfig::load_payloads_from_file(path) {
            Ok(config) => {
                println!("✓ Loaded payload configuration from: {}", path.display());
                config
            }
            Err(e) => {
                eprintln!("⛔ Error loading payload file: {}", e);
                eprintln!("   Please check the file path and YAML syntax.");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("\n⚠️  WARNING: No payload file provided");
        eprintln!("   Using PLACEHOLDER payloads - no real testing will occur");
        eprintln!("   Provide actual test payloads via --payload-file for real scans");
        eprintln!("   See payloads.example.yaml for the required format\n");
        sqli::config::PayloadConfig::default()
    };

    // Build configuration with safety limits enforced
    let config = sqli::config::SqliConfig {
        target,
        max_concurrency: max_concurrency.min(20), // Safety cap at 20
        max_rps: rps.min(50),                     // Safety cap at 50
        timeout_secs: timeout,
        max_depth,
        enable_oob,
        oob_host,
        time_delay_secs: time_delay.min(5),       // Safety cap at 5 seconds
        time_samples,
        payload_config,
        payload_file,
        user_agent: user_agent.unwrap_or_else(|| {
            "netool-sqli-scanner/2.0 (Security Assessment)".to_string()
        }),
        custom_headers,
        cookies,
        follow_redirects: true,
        max_endpoints,
    };

    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("⛔ Configuration error: {}", e);
        eprintln!("   Please check your settings and try again.");
        std::process::exit(1);
    }

    // Dry run mode - validate without scanning
    if dry_run {
        println!("\n{}", "═".repeat(70));
        println!("  🔍 DRY RUN MODE");
        println!("{}", "═".repeat(70));
        println!("Configuration validated successfully:");
        println!("  Target: {}", config.target);
        println!("  Max Concurrency: {}", config.max_concurrency);
        println!("  Requests/sec: {}", config.max_rps);
        println!("  Timeout: {}s", config.timeout_secs);
        println!("  Max Depth: {}", config.max_depth);
        println!("  Time Delay: {}s", config.time_delay_secs);
        println!("  OOB Enabled: {}", config.enable_oob);
        if config.enable_oob {
            println!("  OOB Host: {}", config.oob_host.as_ref().unwrap_or(&"<not set>".to_string()));
        }
        println!("  Payload Source: {}",
                 if config.payload_file.is_some() {
                     config.payload_file.as_ref().unwrap().display().to_string()
                 } else {
                     "placeholders (no real testing)".to_string()
                 }
        );
        println!("\n✅ Dry run complete. Configuration is valid.");
        println!("   Ready for authorized scan (remove --dry-run flag).");
        println!("{}\n", "═".repeat(70));
        return;
    }

    // Perform the actual scan
    println!("\n🚀 Starting SQL injection vulnerability scan");
    println!("   Target: {}", config.target);
    println!("   Scan initiated at: {}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));

    match sqli::scan_target(config).await {
        Ok(results) => {
            // Generate report based on output format
            match output_format.as_str() {
                "json" => {
                    let json = serde_json::to_string_pretty(&results)
                        .expect("Failed to serialize results to JSON");

                    if let Some(path) = output_file {
                        match std::fs::write(&path, json) {
                            Ok(()) => println!("✓ Results saved to: {}", path.display()),
                            Err(e) => eprintln!("⛔ Failed to write output file: {}", e),
                        }
                    } else {
                        println!("{}", json);
                    }
                }
                "yaml" => {
                    let yaml = serde_yaml::to_string(&results)
                        .expect("Failed to serialize results to YAML");

                    if let Some(path) = output_file {
                        match std::fs::write(&path, yaml) {
                            Ok(()) => println!("✓ Results saved to: {}", path.display()),
                            Err(e) => eprintln!("⛔ Failed to write output file: {}", e),
                        }
                    } else {
                        println!("{}", yaml);
                    }
                }
                _ => {
                    // Text output (default)
                    sqli::print_results(&results, short);

                    if let Some(path) = output_file {
                        // For text output to file, capture formatted output
                        let mut text_output = String::new();
                        text_output.push_str(&format!("SQL INJECTION SCAN RESULTS\n"));
                        text_output.push_str(&format!("Target: {}\n", results.target));
                        text_output.push_str(&format!("Vulnerabilities: {}\n", results.vulnerabilities.len()));

                        match std::fs::write(&path, text_output) {
                            Ok(()) => println!("\n✓ Results also saved to: {}", path.display()),
                            Err(e) => eprintln!("\n⛔ Failed to write output file: {}", e),
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("\n⛔ Scan failed: {}", e);
            eprintln!("   Please check your configuration and network connectivity.");
            std::process::exit(1);
        }
    }
}

fn print_sqli_safety_banner(enable_oob: bool, rps: u32, max_concurrency: usize, time_delay: u64) {
    println!("\n{}", "═".repeat(70));
    println!("  SQL INJECTION VULNERABILITY SCANNER - AUTHORIZED USE ONLY");
    println!("{}", "═".repeat(70));
    println!("⚠️  SAFETY CONSTRAINTS ACTIVE:");
    println!("   ✓ Rate limiting: {} req/s maximum", rps);
    println!("   ✓ Concurrency: {} connections maximum", max_concurrency);
    println!("   ✓ Non-destructive testing only");
    println!("   ✓ Time delays: ≤ {}s (safety limited)", time_delay);
    println!("   ✓ OOB testing: {}", if enable_oob { "ENABLED ⚠️" } else { "disabled (safe)" });

    println!("\n📋 Test methodology:");
    println!("   • Boolean-based blind detection (differential analysis)");
    println!("   • Time-based blind detection (statistical validation)");
    println!("   • Error-based detection (passive observation)");
    if enable_oob {
        println!("   • Out-of-band detection (DNS/HTTP callbacks)");
    }

    println!("\n⚖️  LEGAL REMINDER:");
    println!("   Test ONLY systems you own or have explicit written");
    println!("   authorization to assess. Unauthorized testing is illegal.");
    println!("{}\n", "═".repeat(70));
}

// ============================================================================
// DNS OPERATIONS
// ============================================================================

async fn handle_dns(operation: String, target: String) {
    let targets = read_targets(&target);

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let mut handles = Vec::with_capacity(targets.len());

    for t in targets {
        let resolver = resolver.clone();
        let op = operation.clone();

        let handle = tokio::spawn(async move {
            match op.as_str() {
                "resolve" => dns_resolve(&resolver, &t).await,
                "reverse" => dns_reverse(&resolver, &t).await,
                _ => println!("Unknown operation: {}", op),
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn dns_resolve(resolver: &TokioAsyncResolver, domain: &str) {
    match resolver.lookup_ip(domain).await {
        Ok(response) => {
            let ips: Vec<IpAddr> = response.iter().collect();
            println!("[+] {} -> {:?}", domain, ips);
        }
        Err(e) => {
            println!("[-] {} -> Error: {}", domain, e);
        }
    }
}

async fn dns_reverse(resolver: &TokioAsyncResolver, ip_str: &str) {
    match ip_str.parse::<IpAddr>() {
        Ok(ip) => {
            match resolver.reverse_lookup(ip).await {
                Ok(response) => {
                    let names: Vec<String> = response.iter().map(|n| n.to_string()).collect();
                    println!("[+] {} -> {:?}", ip, names);
                }
                Err(e) => {
                    println!("[-] {} -> Error: {}", ip, e);
                }
            }
        }
        Err(e) => {
            println!("[-] Invalid IP address {}: {}", ip_str, e);
        }
    }
}

// ============================================================================
// PING OPERATIONS
// ============================================================================

async fn handle_ping(target: String, count: u32) {
    let targets = read_targets(&target);
    let mut handles = Vec::with_capacity(targets.len());

    for t in targets {
        let handle = tokio::spawn(async move {
            ping_target(&t, count).await;
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn ping_target(target: &str, count: u32) {
    let ip = match target.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            match resolve_hostname(target).await {
                Some(ip) => ip,
                None => {
                    println!("[-] {} -> Failed to resolve", target);
                    return;
                }
            }
        }
    };

    let mut success = 0;
    let mut total_time = Duration::from_secs(0);

    for i in 0..count {
        let start = std::time::Instant::now();
        let addr = format!("{}:80", ip);

        match timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => {
                let duration = start.elapsed();
                total_time += duration;
                success += 1;
                println!("[+] {} -> Reply #{}: time={:?}", ip, i + 1, duration);
            }
            Ok(Err(e)) => {
                println!("[-] {} -> Reply #{}: Connection failed - {}", ip, i + 1, e);
            }
            Err(_) => {
                println!("[-] {} -> Reply #{}: Timeout", ip, i + 1);
            }
        }

        if i < count - 1 {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    let avg_time = if success > 0 {
        total_time / success
    } else {
        Duration::from_secs(0)
    };

    println!("\n--- {} ping statistics ---", ip);
    println!("{} packets transmitted, {} received, {:.1}% packet loss",
             count, success, ((count - success) as f64 / count as f64) * 100.0);
    if success > 0 {
        println!("Average time: {:?}", avg_time);
    }
}

// ============================================================================
// WEB FUZZING OPERATIONS
// ============================================================================

async fn handle_fuzz(
    url: String,
    wordlist_path: Option<String>,
    mode: String,
    concurrent: usize,
    status_filter: Option<String>,
    timeout: u64,
    recursive: bool,
    max_depth: usize,
    extensions: Option<String>,
    baseline: bool,
) {
    println!("\n[*] Advanced Web Fuzzer");
    println!("[*] Target: {}", url);
    println!("[*] Mode: {}", mode);
    println!("[*] Workers: {}", concurrent);
    if recursive {
        println!("[*] Recursive: Yes (max depth: {})", max_depth);
    }

    println!("\n[*] Loading wordlist...");
    let wordlist = match fuzz::load_wordlist(wordlist_path.as_deref()).await {
        Ok(wl) => wl,
        Err(e) => {
            eprintln!("[-] Error loading wordlist: {}", e);
            return;
        }
    };

    println!("[*] Loaded {} words", wordlist.len());

    let status_codes = status_filter.map(|s| {
        s.split(',')
            .filter_map(|code| code.trim().parse::<u16>().ok())
            .collect()
    });

    let ext_list = extensions.map(|s| {
        s.split(',')
            .map(|ext| {
                let trimmed = ext.trim();
                if trimmed.starts_with('.') {
                    trimmed.to_string()
                } else {
                    format!(".{}", trimmed)
                }
            })
            .collect::<Vec<String>>()
    }).unwrap_or_default();

    let options = fuzz::FuzzOptions {
        timeout_secs: timeout,
        max_concurrent: concurrent,
        status_filter: status_codes,
        show_errors: false,
        extensions: ext_list.clone(),
        recursive,
        max_depth,
        baseline_detection: baseline,
        ..Default::default()
    };

    println!("\n[*] Starting fuzzing...\n");
    let start = std::time::Instant::now();

    let results = match mode.as_str() {
        "dir" | "directory" => {
            if recursive {
                fuzz::fuzz_recursive(&url, wordlist, options).await
            } else if !ext_list.is_empty() {
                fuzz::fuzz_with_extensions(&url, wordlist, ext_list, options).await
            } else {
                fuzz::fuzz_directories(&url, wordlist, options).await
            }
        }
        "subdomain" | "sub" => {
            let domain = url.replace("https://", "").replace("http://", "");
            fuzz::fuzz_subdomains(&domain, wordlist, options).await
        }
        "param" | "parameter" => {
            fuzz::fuzz_parameters(&url, wordlist, options).await
        }
        "extensions" | "ext" => {
            if ext_list.is_empty() {
                eprintln!("[-] No extensions specified! Use --extensions \".php,.bak\"");
                return;
            }
            fuzz::fuzz_with_extensions(&url, wordlist, ext_list, options).await
        }
        _ => {
            eprintln!("[-] Invalid mode. Use: dir, subdomain, param, or extensions");
            return;
        }
    };

    let duration = start.elapsed();

    println!("\n{}", "=".repeat(90));
    println!("[+] Fuzzing completed in {:.2}s", duration.as_secs_f64());
    println!("[+] Found {} results", results.len());
    println!("{}", "=".repeat(90));

    if !results.is_empty() {
        println!("\n{:<8} {:<12} {:<10} {}", "Status", "Size", "Time", "URL");
        println!("{}", "-".repeat(90));

        for result in &results {
            let status_icon = match result.status_code {
                200 => "✓",
                301 | 302 | 307 | 308 => "→",
                403 => "✗",
                _ => " ",
            };

            println!(
                "{} {:<6} {:<12} {:<10} {}",
                status_icon,
                result.status_code,
                result.content_length,
                format!("{}ms", result.duration_ms),
                result.url
            );

            // Show findings if any
            if !result.findings.is_empty() {
                for finding in &result.findings {
                    println!("    ├─ {}", finding);
                }
            }
        }
    }
}
async fn handle_get(target: String, timeout_secs: u64) {
    let targets = read_targets(&target);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .unwrap_or_else(|e| {
            eprintln!("Failed to create HTTP client: {}", e);
            std::process::exit(1);
        });

    let mut handles = Vec::with_capacity(targets.len());

    for url in targets {
        let client = client.clone();

        let handle = tokio::spawn(async move {
            http_get(&client, &url).await;
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn http_get(client: &reqwest::Client, url: &str) {
    let url_formatted = if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("http://{}", url)
    } else {
        url.to_string()
    };

    let start = std::time::Instant::now();

    match client.get(&url_formatted).send().await {
        Ok(response) => {
            let duration = start.elapsed();
            let status = response.status();
            let content_length = response.content_length().unwrap_or(0);

            println!("[+] {} -> Status: {}, Size: {} bytes, Time: {:?}",
                     url_formatted, status, content_length, duration);
        }
        Err(e) => {
            let duration = start.elapsed();
            println!("[-] {} -> Error: {} (Time: {:?})", url_formatted, e, duration);
        }
    }
}

// ============================================================================
// DNS DIG OPERATIONS
// ============================================================================

async fn handle_dig(domain: String, record_type: String, nameserver: Option<IpAddr>, short: bool, all: bool) {
    if all {
        match dig::dig_any(&domain, nameserver).await {
            Ok(results) => {
                for result in results {
                    let options = dig::DigOptions {
                        query_type: result.query_type,
                        nameserver,
                        show_stats: false,
                        trace: false,
                        short,
                    };
                    result.display(&options);
                }
            }
            Err(e) => {
                eprintln!("Error performing ANY query: {}", e);
            }
        }
    } else {
        let rec_type = match dig::parse_record_type(&record_type) {
            Some(rt) => rt,
            None => {
                eprintln!("Invalid record type: {}. Valid types: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA, ANY", record_type);
                return;
            }
        };

        let options = dig::DigOptions {
            query_type: rec_type,
            nameserver,
            show_stats: true,
            trace: false,
            short,
        };

        match dig::dig(&domain, options).await {
            Ok(result) => {
                let display_options = dig::DigOptions {
                    query_type: rec_type,
                    nameserver,
                    show_stats: true,
                    trace: false,
                    short,
                };
                result.display(&display_options);
            }
            Err(e) => {
                eprintln!("Error performing dig: {}", e);
            }
        }
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

async fn resolve_hostname(hostname: &str) -> Option<IpAddr> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    match resolver.lookup_ip(hostname).await {
        Ok(response) => response.iter().next(),
        Err(_) => None,
    }
}

fn read_targets(target: &str) -> Vec<String> {
    if let Ok(content) = fs::read_to_string(target) {
        content
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect()
    } else {
        vec![target.to_string()]
    }
}