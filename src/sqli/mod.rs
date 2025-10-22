// src/sqli/mod.rs
// SQL Injection Scanner Module for netool
// SAFETY: Designed for AUTHORIZED testing only with strict safety constraints

pub mod config;
pub mod crawler;
pub mod error;
pub mod heuristics;
pub mod http_client;
pub mod tester;
pub mod types;

use config::SqliConfig;
use std::sync::Arc;
use types::ScanResults;
use tracing::info;

/// Main entry point for SQL injection scanning
pub async fn scan_target(config: SqliConfig) -> Result<ScanResults, Box<dyn std::error::Error>> {
    let start_time = chrono::Utc::now();

    info!("🔍 Starting SQL injection scan");
    info!("Target: {}", config.target);

    // Phase 1: Crawl target
    info!("Phase 1/4: Crawling target...");
    let crawler = crawler::Crawler::new(Arc::new(config.clone()))?;
    let endpoints = crawler.crawl().await?;
    info!("✓ Found {} endpoints", endpoints.len());

    // Phase 2: Passive analysis
    info!("Phase 2/4: Passive analysis...");
    let _passive_findings = heuristics::Heuristics::analyze_endpoints(&endpoints).await;
    info!("✓ Passive analysis complete");

    // Phase 3: Active testing
    info!("Phase 3/4: Active testing (safe probes only)...");
    let tester = tester::SqliTester::new(Arc::new(config.clone()))?;
    let mut vulnerabilities = Vec::new();
    let mut total_tests = 0;

    for endpoint in &endpoints {
        for parameter in &endpoint.parameters {
            total_tests += 1;

            if let Some(result) = tester.test_parameter(endpoint, parameter).await? {
                info!("⚠️ Potential vulnerability found: {}.{}", endpoint.url, parameter.name);
                vulnerabilities.push(result);
            }
        }
    }

    info!("✓ Active testing complete ({} tests)", total_tests);

    // Phase 4: Generate results
    info!("Phase 4/4: Compiling results...");

    let end_time = chrono::Utc::now();

    let summary = types::ScanSummary {
        total_requests: total_tests,
        high_confidence: vulnerabilities.iter().filter(|v| matches!(v.confidence, types::ConfidenceLevel::High)).count(),
        medium_confidence: vulnerabilities.iter().filter(|v| matches!(v.confidence, types::ConfidenceLevel::Medium)).count(),
        low_confidence: vulnerabilities.iter().filter(|v| matches!(v.confidence, types::ConfidenceLevel::Low)).count(),
        verified_count: vulnerabilities.iter().filter(|v| v.verified).count(),
        boolean_based: vulnerabilities.iter().filter(|v| matches!(v.vulnerability_type, types::VulnerabilityType::BooleanBased)).count(),
        time_based: vulnerabilities.iter().filter(|v| matches!(v.vulnerability_type, types::VulnerabilityType::TimeBased)).count(),
        error_based: vulnerabilities.iter().filter(|v| matches!(v.vulnerability_type, types::VulnerabilityType::ErrorBased)).count(),
        oob_based: vulnerabilities.iter().filter(|v| matches!(v.vulnerability_type, types::VulnerabilityType::OutOfBand)).count(),
    };

    let results = ScanResults {
        target: config.target.clone(),
        scan_start: start_time.to_rfc3339(),
        scan_end: end_time.to_rfc3339(),
        endpoints_discovered: endpoints.len(),
        parameters_tested: total_tests,
        vulnerabilities,
        summary: summary.clone(),
        configuration: types::ScanConfigSummary {
            max_concurrency: config.max_concurrency,
            max_rps: config.max_rps,
            oob_enabled: config.enable_oob,
            payloads_source: if config.payload_file.is_some() {
                "custom file".to_string()
            } else {
                "placeholders (no real testing)".to_string()
            },
        },
    };

    info!("✅ Scan complete");
    info!("   Vulnerabilities found: {}", results.vulnerabilities.len());
    info!("   High confidence: {}", summary.high_confidence);
    info!("   Verified: {}", summary.verified_count);

    Ok(results)
}

/// Print scan results in human-readable format
pub fn print_results(results: &ScanResults, short: bool) {
    println!("\n{}", "═".repeat(70));
    println!("  SQL INJECTION SCAN RESULTS");
    println!("{}", "═".repeat(70));
    println!("Target: {}", results.target);
    println!("Scan duration: {} to {}", results.scan_start, results.scan_end);
    println!();

    println!("📊 Summary:");
    println!("   Endpoints discovered: {}", results.endpoints_discovered);
    println!("   Parameters tested: {}", results.parameters_tested);
    println!("   Vulnerabilities found: {}", results.vulnerabilities.len());
    println!();

    if results.vulnerabilities.is_empty() {
        println!("✅ No SQL injection vulnerabilities detected");
        println!();
        return;
    }

    println!("⚠️ Confidence breakdown:");
    println!("   High:   {}", results.summary.high_confidence);
    println!("   Medium: {}", results.summary.medium_confidence);
    println!("   Low:    {}", results.summary.low_confidence);
    println!("   Verified: {}", results.summary.verified_count);
    println!();

    println!("🎯 Vulnerability types:");
    println!("   Boolean-based: {}", results.summary.boolean_based);
    println!("   Time-based:    {}", results.summary.time_based);
    println!("   Error-based:   {}", results.summary.error_based);
    println!("   Out-of-band:   {}", results.summary.oob_based);
    println!();

    if !short {
        println!("📋 Detailed findings:");
        println!("{}", "-".repeat(70));

        for (i, vuln) in results.vulnerabilities.iter().enumerate() {
            println!("\n[{}] {} - {:?}", i + 1, vuln.endpoint, vuln.vulnerability_type);
            println!("    Parameter: {} ({:?})", vuln.parameter, vuln.location);
            println!("    Confidence: {:?}", vuln.confidence);
            println!("    Verified: {}", if vuln.verified { "✓" } else { "✗" });
            println!("    Evidence count: {}", vuln.evidence.len());

            if let Some(first_evidence) = vuln.evidence.first() {
                println!("    Test type: {}", first_evidence.test_type);
                println!("    Description: {}", first_evidence.description);
            }
        }

        println!("\n{}", "-".repeat(70));
        println!("\n🛡️ Remediation recommendations:");
        println!("   1. Use parameterized queries/prepared statements");
        println!("   2. Implement input validation with allowlists");
        println!("   3. Apply least-privilege database access");
        println!("   4. Enable error suppression in production");
        println!("   5. Deploy a Web Application Firewall (WAF)");
        println!("   6. Regular security audits and patching");
    }

    println!("\n{}", "═".repeat(70));
}