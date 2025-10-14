#!/usr/bin/env python3
"""
Security Analysis Example using netool
Demonstrates HTTP GET with redirect following and vulnerability analysis
"""

import asyncio
import netool


def print_security_report(result):
    """Pretty print security analysis results"""
    print("\n" + "=" * 70)
    print("HTTP Security Analysis Report")
    print("=" * 70)

    print(f"\n[*] Request Information:")
    print(f"    Original URL:  {result['url']}")
    print(f"    Final URL:     {result['final_url']}")
    print(f"    Status Code:   {result['status']}")
    print(f"    Content Size:  {result['content_length']} bytes")
    print(f"    Duration:      {result['duration_ms']}ms")
    print(f"    Redirected:    {result['redirected']}")

    if 'security_analysis' in result:
        sec = result['security_analysis']
        risk_score = sec['risk_score']

        # Determine risk level
        if risk_score >= 50:
            risk_level = "CRITICAL"
            risk_color = "🔴"
        elif risk_score >= 30:
            risk_level = "HIGH"
            risk_color = "🟠"
        elif risk_score >= 15:
            risk_level = "MEDIUM"
            risk_color = "🟡"
        elif risk_score > 0:
            risk_level = "LOW"
            risk_color = "🟢"
        else:
            risk_level = "SECURE"
            risk_color = "✅"

        print(f"\n{risk_color} Overall Risk Score: {risk_score}/100 ({risk_level})")

        if sec['missing_headers']:
            print(f"\n[!] Missing Security Headers ({len(sec['missing_headers'])}):")
            for header in sec['missing_headers']:
                print(f"    • {header}")

        if sec['insecure_headers']:
            print(f"\n[!] Insecure Headers ({len(sec['insecure_headers'])}):")
            for header in sec['insecure_headers']:
                print(f"    • {header}")

        if sec['vulnerabilities']:
            print(f"\n[!] Vulnerabilities Detected ({len(sec['vulnerabilities'])}):")
            for vuln in sec['vulnerabilities']:
                print(f"    • {vuln}")

        if risk_score == 0:
            print(f"\n✅ No security issues detected!")

    print("\n" + "=" * 70)


async def test_single_site(url):
    """Test a single website"""
    print(f"\n[*] Analyzing: {url}")
    print("-" * 70)

    result = await netool.http_get_secure(
        url,
        follow_redirects=True,
        max_redirects=10,
        timeout=30,
        analyze_security=True
    )

    if result['success']:
        print_security_report(result)
    else:
        print(f"[!] Error: {result['error']}")


async def test_multiple_sites():
    """Test multiple websites concurrently"""
    print("\n" + "=" * 70)
    print("Batch Security Analysis")
    print("=" * 70)

    urls = [
        "https://example.com",
        "http://example.com",  # Test HTTP
        "https://google.com",
        "https://github.com",
    ]

    print(f"\n[*] Scanning {len(urls)} websites...")

    tasks = [
        netool.http_get_secure(
            url,
            follow_redirects=True,
            analyze_security=True
        )
        for url in urls
    ]

    results = await asyncio.gather(*tasks)

    # Summary table
    print("\n" + "=" * 70)
    print("Security Summary")
    print("=" * 70)
    print(f"\n{'URL':<35} {'Status':<8} {'Risk':<6} {'Issues':<10}")
    print("-" * 70)

    for result in results:
        if result['success']:
            url = result['url'][:32] + "..." if len(result['url']) > 35 else result['url']
            status = result['status']

            if 'security_analysis' in result:
                risk = result['security_analysis']['risk_score']
                issues = (
                        len(result['security_analysis']['missing_headers']) +
                        len(result['security_analysis']['insecure_headers']) +
                        len(result['security_analysis']['vulnerabilities'])
                )
                print(f"{url:<35} {status:<8} {risk:<6} {issues:<10}")
            else:
                print(f"{url:<35} {status:<8} {'N/A':<6} {'N/A':<10}")
        else:
            url = result['url'][:32] + "..." if len(result['url']) > 35 else result['url']
            print(f"{url:<35} {'ERROR':<8} {'N/A':<6} {'N/A':<10}")


async def test_redirect_chain():
    """Test redirect following"""
    print("\n" + "=" * 70)
    print("Redirect Chain Analysis")
    print("=" * 70)

    # Test a URL that likely redirects
    url = "http://github.com"

    print(f"\n[*] Testing redirects: {url}")

    result = await netool.http_get_secure(
        url,
        follow_redirects=True,
        max_redirects=10,
        analyze_security=True
    )

    if result['success']:
        if result['redirected']:
            print(f"\n[+] Redirect detected:")
            print(f"    {result['url']} -> {result['final_url']}")

            # Check for security implications
            if result['url'].startswith('http://') and result['final_url'].startswith('https://'):
                print(f"    ✅ Good: HTTP upgraded to HTTPS")
            elif result['url'].startswith('https://') and result['final_url'].startswith('http://'):
                print(f"    ⚠️  WARNING: HTTPS downgraded to HTTP!")
        else:
            print(f"\n[*] No redirects detected")

        # Show headers relevant to redirects
        if 'headers' in result:
            headers = result['headers']
            redirect_headers = ['location', 'refresh', 'strict-transport-security']

            print(f"\n[*] Redirect-related headers:")
            for header in redirect_headers:
                if header in headers:
                    print(f"    {header}: {headers[header]}")


async def compare_http_vs_https():
    """Compare HTTP vs HTTPS security"""
    print("\n" + "=" * 70)
    print("HTTP vs HTTPS Comparison")
    print("=" * 70)

    domain = "example.com"

    print(f"\n[*] Testing {domain} with both protocols...")

    http_result = await netool.http_get_secure(
        f"http://{domain}",
        follow_redirects=False,
        analyze_security=True
    )

    https_result = await netool.http_get_secure(
        f"https://{domain}",
        follow_redirects=False,
        analyze_security=True
    )

    print(f"\n{'Protocol':<15} {'Status':<10} {'Risk Score':<15} {'Redirected':<12}")
    print("-" * 70)

    if http_result['success']:
        http_risk = http_result.get('security_analysis', {}).get('risk_score', 'N/A')
        print(f"{'HTTP':<15} {http_result['status']:<10} {http_risk:<15} {str(http_result['redirected']):<12}")

    if https_result['success']:
        https_risk = https_result.get('security_analysis', {}).get('risk_score', 'N/A')
        print(f"{'HTTPS':<15} {https_result['status']:<10} {https_risk:<15} {str(https_result['redirected']):<12}")

    print("\n[*] Recommendation:")
    if http_result['success'] and https_result['success']:
        if http_result['redirected'] and http_result['final_url'].startswith('https://'):
            print("    ✅ HTTP automatically redirects to HTTPS - Good!")
        else:
            print("    ⚠️  HTTP does not redirect to HTTPS - Consider implementing redirect")


async def vulnerability_scan_example():
    """Example of scanning for common vulnerabilities"""
    print("\n" + "=" * 70)
    print("Vulnerability Scanning Example")
    print("=" * 70)

    # Test sites with different security postures
    test_cases = [
        ("https://example.com", "Well-configured site"),
        ("http://example.com", "Insecure HTTP"),
    ]

    for url, description in test_cases:
        print(f"\n[*] Test Case: {description}")
        print(f"    URL: {url}")

        result = await netool.http_get_secure(url, analyze_security=True)

        if result['success'] and 'security_analysis' in result:
            sec = result['security_analysis']

            # Categorize vulnerabilities
            critical = [v for v in sec['vulnerabilities'] if 'CRITICAL' in v]
            high = [v for v in sec['vulnerabilities'] if 'HIGH' in v]
            medium = [v for v in sec['vulnerabilities'] if 'MEDIUM' in v]

            print(f"    Risk Score: {sec['risk_score']}/100")
            print(f"    Critical: {len(critical)}, High: {len(high)}, Medium: {len(medium)}")

            if critical:
                print(f"    ⚠️  Critical issues found!")


async def main():
    """Main function with menu"""
    print("\n" + "=" * 70)
    print("Network Security Analysis Tool")
    print("Powered by netool (Rust)")
    print("=" * 70)

    while True:
        print("\n[*] Select a test:")
        print("    1. Test single website")
        print("    2. Batch scan multiple websites")
        print("    3. Test redirect chains")
        print("    4. Compare HTTP vs HTTPS")
        print("    5. Vulnerability scan example")
        print("    6. Run all tests")
        print("    0. Exit")

        choice = input("\nEnter choice (0-6): ").strip()

        if choice == '1':
            url = input("Enter URL to test: ").strip()
            if url:
                await test_single_site(url)

        elif choice == '2':
            await test_multiple_sites()

        elif choice == '3':
            await test_redirect_chain()

        elif choice == '4':
            await compare_http_vs_https()

        elif choice == '5':
            await vulnerability_scan_example()

        elif choice == '6':
            print("\n[*] Running all tests...")
            await test_single_site("https://example.com")
            await test_multiple_sites()
            await test_redirect_chain()
            await compare_http_vs_https()
            await vulnerability_scan_example()
            print("\n[+] All tests completed!")

        elif choice == '0':
            print("\n[*] Exiting...")
            break

        else:
            print("\n[!] Invalid choice. Please try again.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
    except Exception as e:
        print(f"\n[!] Error: {e}")