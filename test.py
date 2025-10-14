#!/usr/bin/env python3
"""
Batch Security Testing Script for netool
Tests the new http_get_secure function with multiple sites
"""

import asyncio
import netool
from datetime import datetime
import json

# Test sites with different security profiles
TEST_SITES = [
    # Well-configured sites
    "https://gitlab.blacklanternsecurity.com",

]


async def test_single_site(url):
    """Test a single site and return formatted results"""
    print(f"[*] Testing: {url}")

    try:
        result = await netool.http_get_secure(
            url,
            follow_redirects=True,
            max_redirects=10,
            timeout=30,
            analyze_security=True
        )

        if result['success']:
            sec = result['security_analysis']
            return {
                'url': url,
                'status': 'SUCCESS',
                'http_status': result['status'],
                'final_url': result['final_url'],
                'redirected': result['redirected'],
                'duration_ms': result['duration_ms'],
                'risk_score': sec['risk_score'],
                'missing_headers': len(sec['missing_headers']),
                'insecure_headers': len(sec['insecure_headers']),
                'vulnerabilities': len(sec['vulnerabilities']),
                'details': {
                    'missing': sec['missing_headers'],
                    'insecure': sec['insecure_headers'],
                    'vulns': sec['vulnerabilities']
                }
            }
        else:
            return {
                'url': url,
                'status': 'FAILED',
                'error': result.get('error', 'Unknown error')
            }

    except Exception as e:
        return {
            'url': url,
            'status': 'ERROR',
            'error': str(e)
        }


async def batch_test_sequential():
    """Test sites one by one (slower but safer)"""
    print("\n" + "=" * 70)
    print("SEQUENTIAL BATCH TEST")
    print("=" * 70)

    results = []
    start_time = datetime.now()

    for url in TEST_SITES:
        result = await test_single_site(url)
        results.append(result)

        # Brief pause between requests
        await asyncio.sleep(0.5)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Sequential test completed in {duration:.2f} seconds")
    return results


async def batch_test_concurrent(max_concurrent=5):
    """Test sites concurrently (faster)"""
    print("\n" + "=" * 70)
    print(f"CONCURRENT BATCH TEST (max {max_concurrent} workers)")
    print("=" * 70)

    start_time = datetime.now()

    # Create semaphore to limit concurrency
    sem = asyncio.Semaphore(max_concurrent)

    async def test_with_limit(url):
        async with sem:
            return await test_single_site(url)

    # Run all tests concurrently (but limited by semaphore)
    tasks = [test_with_limit(url) for url in TEST_SITES]
    results = await asyncio.gather(*tasks)

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Concurrent test completed in {duration:.2f} seconds")
    return results


def print_results_table(results):
    """Print results in a nice table format"""
    print("\n" + "=" * 120)
    print("SECURITY SCAN RESULTS")
    print("=" * 120)

    # Header
    print(f"\n{'URL':<35} {'Status':<8} {'HTTP':<6} {'Risk':<6} {'Issues':<8} {'Time':<10} {'Redirected':<12}")
    print("-" * 120)

    # Results
    for result in results:
        if result['status'] == 'SUCCESS':
            url = result['url'][:32] + "..." if len(result['url']) > 35 else result['url']
            status = "✅ OK"
            http_status = result['http_status']
            risk = result['risk_score']
            issues = result['missing_headers'] + result['insecure_headers'] + result['vulnerabilities']
            time_ms = f"{result['duration_ms']}ms"
            redirected = "Yes" if result['redirected'] else "No"

            # Color code risk
            if risk >= 50:
                risk_display = f"🔴 {risk}"
            elif risk >= 30:
                risk_display = f"🟠 {risk}"
            elif risk >= 15:
                risk_display = f"🟡 {risk}"
            else:
                risk_display = f"🟢 {risk}"

            print(
                f"{url:<35} {status:<8} {http_status:<6} {risk_display:<6} {issues:<8} {time_ms:<10} {redirected:<12}")
        else:
            url = result['url'][:32] + "..." if len(result['url']) > 35 else result['url']
            error = result.get('error', 'Unknown')[:40]
            print(f"{url:<35} ❌ FAIL  {'N/A':<6} {'N/A':<6} {'N/A':<8} {'N/A':<10} {error}")


def print_detailed_results(results):
    """Print detailed findings for each site"""
    print("\n" + "=" * 120)
    print("DETAILED FINDINGS")
    print("=" * 120)

    for result in results:
        if result['status'] != 'SUCCESS':
            continue

        print(f"\n{'─' * 120}")
        print(f"🔍 {result['url']}")
        print(f"{'─' * 120}")

        print(f"\n📊 Summary:")
        print(f"   Status Code: {result['http_status']}")
        print(f"   Risk Score: {result['risk_score']}/100")
        print(f"   Response Time: {result['duration_ms']}ms")

        if result['redirected']:
            print(f"   Redirected: {result['url']} → {result['final_url']}")

        details = result['details']

        if details['missing']:
            print(f"\n⚠️  Missing Security Headers ({len(details['missing'])}):")
            for item in details['missing'][:5]:  # Show first 5
                print(f"   • {item}")
            if len(details['missing']) > 5:
                print(f"   ... and {len(details['missing']) - 5} more")

        if details['insecure']:
            print(f"\n⚠️  Insecure Headers ({len(details['insecure'])}):")
            for item in details['insecure']:
                print(f"   • {item}")

        if details['vulns']:
            print(f"\n🚨 Vulnerabilities ({len(details['vulns'])}):")
            for item in details['vulns']:
                print(f"   • {item}")


def calculate_statistics(results):
    """Calculate and print statistics"""
    print("\n" + "=" * 120)
    print("STATISTICS")
    print("=" * 120)

    successful = [r for r in results if r['status'] == 'SUCCESS']
    failed = [r for r in results if r['status'] != 'SUCCESS']

    if not successful:
        print("\n❌ No successful scans to analyze")
        return

    risk_scores = [r['risk_score'] for r in successful]
    avg_risk = sum(risk_scores) / len(risk_scores)
    max_risk = max(risk_scores)
    min_risk = min(risk_scores)

    high_risk = len([r for r in successful if r['risk_score'] >= 30])
    medium_risk = len([r for r in successful if 15 <= r['risk_score'] < 30])
    low_risk = len([r for r in successful if r['risk_score'] < 15])

    print(f"\n📈 Risk Analysis:")
    print(f"   Total Scanned: {len(results)}")
    print(f"   Successful: {len(successful)}")
    print(f"   Failed: {len(failed)}")
    print(f"\n   Average Risk Score: {avg_risk:.1f}/100")
    print(f"   Highest Risk: {max_risk}/100")
    print(f"   Lowest Risk: {min_risk}/100")
    print(f"\n   🔴 High Risk (≥30): {high_risk}")
    print(f"   🟡 Medium Risk (15-29): {medium_risk}")
    print(f"   🟢 Low Risk (<15): {low_risk}")

    # Response time stats
    durations = [r['duration_ms'] for r in successful]
    avg_duration = sum(durations) / len(durations)
    print(f"\n⏱️  Performance:")
    print(f"   Average Response Time: {avg_duration:.0f}ms")
    print(f"   Fastest: {min(durations)}ms")
    print(f"   Slowest: {max(durations)}ms")


def save_results_json(results, filename="security_scan_results.json"):
    """Save results to JSON file"""
    output = {
        'scan_date': datetime.now().isoformat(),
        'total_sites': len(results),
        'results': results
    }

    with open(filename, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n💾 Results saved to: {filename}")


async def main():
    print("\n" + "=" * 120)
    print("🔒 NETOOL SECURITY SCANNER - BATCH TEST")
    print("=" * 120)
    print(f"\nStarting scan at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Testing {len(TEST_SITES)} sites...")

    # Run tests
    print("\n[1/2] Running sequential test...")
    results_seq = await batch_test_sequential()

    print("\n[2/2] Running concurrent test...")
    results_concurrent = await batch_test_concurrent(max_concurrent=5)

    # Use concurrent results for analysis (faster and same results)
    results = results_concurrent

    # Print results
    print_results_table(results)
    print_detailed_results(results)
    calculate_statistics(results)

    # Save to file
    save_results_json(results)

    print("\n" + "=" * 120)
    print("✅ BATCH TEST COMPLETE")
    print("=" * 120)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback

        traceback.print_exc()