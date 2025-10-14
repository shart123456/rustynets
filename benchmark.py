#!/usr/bin/env python3
"""
Network Tool - Rust vs Python Performance Benchmark
Compares Rust (via PyO3) and pure Python implementations
"""

import asyncio
import random
import time
import socket
from typing import List, Dict, Any, Tuple
import netool

# Pure Python DNS implementation using socket
try:
    import dns.resolver
    import dns.reversename

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    print("Warning: dnspython not installed. Install with: pip install dnspython")

try:
    import aiohttp

    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    print("Warning: aiohttp not installed. Install with: pip install aiohttp")


def generate_random_ips(count: int) -> List[str]:
    """Generate random valid IP addresses."""
    if count < 1 or count > 999_999_999:
        raise ValueError("Count must be between 1 and 999,999,999")

    ips = []
    for _ in range(count):
        octets = [
            random.randint(1, 223),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(1, 254)
        ]
        ips.append(f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}")

    return ips


def generate_test_domains(count: int) -> List[str]:
    """Generate test domain names."""
    popular_domains = [
        "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
        "reddit.com", "twitter.com", "instagram.com", "linkedin.com", "netflix.com",
        "github.com", "stackoverflow.com", "microsoft.com", "apple.com", "cloudflare.com",
        "mozilla.org", "debian.org", "ubuntu.com", "python.org", "rust-lang.org"
    ]

    domains = []
    for i in range(count):
        domains.append(popular_domains[i % len(popular_domains)])

    return domains


def generate_test_urls(count: int) -> List[str]:
    """Generate test URLs."""
    base_urls = [
        "https://google.com", "https://github.com", "https://stackoverflow.com",
        "https://python.org", "https://rust-lang.org", "https://wikipedia.org",
        "https://example.com", "https://httpbin.org/get", "https://api.github.com"
    ]

    urls = []
    for i in range(count):
        urls.append(base_urls[i % len(base_urls)])

    return urls


def generate_common_ports(count: int = 100) -> List[int]:
    """Generate list of common ports to scan."""
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 27017, 5432
    ]

    if count <= len(common_ports):
        return common_ports[:count]

    ports = common_ports.copy()
    while len(ports) < count:
        port = random.randint(1, 65535)
        if port not in ports:
            ports.append(port)

    return ports[:count]


# ============================================================================
# PURE PYTHON IMPLEMENTATIONS
# ============================================================================

async def python_dns_resolve(domain: str) -> Dict[str, Any]:
    """Pure Python DNS resolve using dnspython."""
    if not HAS_DNSPYTHON:
        return {"domain": domain, "error": "dnspython not installed", "success": False}

    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, 'A')
        ips = [str(rdata) for rdata in answers]
        return {"domain": domain, "ips": ips, "success": True}
    except Exception as e:
        return {"domain": domain, "error": str(e), "success": False}


async def python_http_get(url: str, timeout: int = 10) -> Dict[str, Any]:
    """Pure Python HTTP GET using aiohttp."""
    if not HAS_AIOHTTP:
        return {"url": url, "error": "aiohttp not installed", "success": False}

    start = time.time()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                content = await response.read()
                duration_ms = int((time.time() - start) * 1000)
                return {
                    "url": url,
                    "status": response.status,
                    "content_length": len(content),
                    "duration_ms": duration_ms,
                    "success": True
                }
    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        return {"url": url, "error": str(e), "duration_ms": duration_ms, "success": False}


async def python_port_scan(host: str, ports: List[int], timeout: int = 2) -> Dict[str, Any]:
    """Pure Python port scanner using asyncio."""
    start = time.time()
    open_ports = []
    closed_ports = []

    async def check_port(port: int):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return port, True
        except:
            return port, False

    tasks = [check_port(port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, tuple):
            port, is_open = result
            if is_open:
                open_ports.append(port)
            else:
                closed_ports.append(port)

    duration_ms = int((time.time() - start) * 1000)

    return {
        "host": host,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "total_ports": len(ports),
        "duration_ms": duration_ms,
        "success": True
    }


# ============================================================================
# BENCHMARK FUNCTIONS
# ============================================================================

async def benchmark_dns_resolve(domains: List[str], batch_size: int = 100) -> Dict[str, Any]:
    """Benchmark DNS resolution: Rust vs Python."""
    print(f"\n{'=' * 80}")
    print(f"BENCHMARK: DNS Resolution")
    print(f"Test data: {len(domains):,} domains")
    print(f"Batch size: {batch_size}")
    print(f"{'=' * 80}\n")

    results = {}

    # Benchmark Rust implementation
    print("🦀 Testing Rust implementation...")
    start_time = time.time()

    rust_successful = 0
    for i in range(0, len(domains), batch_size):
        batch = domains[i:i + batch_size]
        tasks = [netool.dns_resolve(domain) for domain in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        rust_successful += sum(1 for r in batch_results if isinstance(r, dict) and r.get("success"))

    rust_time = time.time() - start_time
    rust_rate = len(domains) / rust_time

    print(f"   Time: {rust_time:.3f}s")
    print(f"   Rate: {rust_rate:.2f} req/s")
    print(f"   Successful: {rust_successful}/{len(domains)}")

    results['rust'] = {
        'time': rust_time,
        'rate': rust_rate,
        'successful': rust_successful
    }

    # Benchmark Python implementation
    if HAS_DNSPYTHON:
        print("\n🐍 Testing Python implementation...")
        start_time = time.time()

        python_successful = 0
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i + batch_size]
            tasks = [python_dns_resolve(domain) for domain in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            python_successful += sum(1 for r in batch_results if isinstance(r, dict) and r.get("success"))

        python_time = time.time() - start_time
        python_rate = len(domains) / python_time

        print(f"   Time: {python_time:.3f}s")
        print(f"   Rate: {python_rate:.2f} req/s")
        print(f"   Successful: {python_successful}/{len(domains)}")

        results['python'] = {
            'time': python_time,
            'rate': python_rate,
            'successful': python_successful
        }

        speedup = python_time / rust_time
        print(f"\n{'=' * 80}")
        print(f"📊 RESULTS:")
        print(f"   Rust is {speedup:.2f}x faster than Python")
        print(f"   Time saved: {python_time - rust_time:.3f}s ({((python_time - rust_time) / python_time * 100):.1f}%)")
        print(f"{'=' * 80}")
    else:
        print("\n⚠️  Skipping Python benchmark (dnspython not installed)")

    return results


async def benchmark_http_get(urls: List[str], batch_size: int = 20) -> Dict[str, Any]:
    """Benchmark HTTP GET: Rust vs Python."""
    print(f"\n{'=' * 80}")
    print(f"BENCHMARK: HTTP GET Requests")
    print(f"Test data: {len(urls):,} URLs")
    print(f"Batch size: {batch_size}")
    print(f"{'=' * 80}\n")

    results = {}

    # Benchmark Rust implementation
    print("🦀 Testing Rust implementation...")
    start_time = time.time()

    rust_successful = 0
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i + batch_size]
        tasks = [netool.http_get(url, timeout=10) for url in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        rust_successful += sum(1 for r in batch_results if isinstance(r, dict) and r.get("success"))

    rust_time = time.time() - start_time
    rust_rate = len(urls) / rust_time

    print(f"   Time: {rust_time:.3f}s")
    print(f"   Rate: {rust_rate:.2f} req/s")
    print(f"   Successful: {rust_successful}/{len(urls)}")

    results['rust'] = {
        'time': rust_time,
        'rate': rust_rate,
        'successful': rust_successful
    }

    # Benchmark Python implementation
    if HAS_AIOHTTP:
        print("\n🐍 Testing Python implementation...")
        start_time = time.time()

        python_successful = 0
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            tasks = [python_http_get(url, timeout=10) for url in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            python_successful += sum(1 for r in batch_results if isinstance(r, dict) and r.get("success"))

        python_time = time.time() - start_time
        python_rate = len(urls) / python_time

        print(f"   Time: {python_time:.3f}s")
        print(f"   Rate: {python_rate:.2f} req/s")
        print(f"   Successful: {python_successful}/{len(urls)}")

        results['python'] = {
            'time': python_time,
            'rate': python_rate,
            'successful': python_successful
        }

        speedup = python_time / rust_time
        print(f"\n{'=' * 80}")
        print(f"📊 RESULTS:")
        print(f"   Rust is {speedup:.2f}x faster than Python")
        print(f"   Time saved: {python_time - rust_time:.3f}s ({((python_time - rust_time) / python_time * 100):.1f}%)")
        print(f"{'=' * 80}")
    else:
        print("\n⚠️  Skipping Python benchmark (aiohttp not installed)")

    return results


async def benchmark_port_scan(targets: List[Tuple[str, List[int]]], batch_size: int = 10) -> Dict[str, Any]:
    """Benchmark port scanning: Rust vs Python."""
    print(f"\n{'=' * 80}")
    print(f"BENCHMARK: Port Scanning")
    print(f"Test data: {len(targets):,} targets")
    print(f"Batch size: {batch_size}")
    print(f"{'=' * 80}\n")

    results = {}

    # Benchmark Rust implementation
    print("🦀 Testing Rust implementation...")
    start_time = time.time()

    rust_successful = 0
    rust_total_open = 0
    for i in range(0, len(targets), batch_size):
        batch = targets[i:i + batch_size]
        tasks = [netool.port_scan(host, ports, timeout=2) for host, ports in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in batch_results:
            if isinstance(r, dict) and r.get("success"):
                rust_successful += 1
                rust_total_open += len(r.get("open_ports", []))

    rust_time = time.time() - start_time
    rust_rate = len(targets) / rust_time

    print(f"   Time: {rust_time:.3f}s")
    print(f"   Rate: {rust_rate:.2f} scans/s")
    print(f"   Successful: {rust_successful}/{len(targets)}")
    print(f"   Open ports found: {rust_total_open}")

    results['rust'] = {
        'time': rust_time,
        'rate': rust_rate,
        'successful': rust_successful,
        'open_ports': rust_total_open
    }

    # Benchmark Python implementation
    print("\n🐍 Testing Python implementation...")
    start_time = time.time()

    python_successful = 0
    python_total_open = 0
    for i in range(0, len(targets), batch_size):
        batch = targets[i:i + batch_size]
        tasks = [python_port_scan(host, ports, timeout=2) for host, ports in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in batch_results:
            if isinstance(r, dict) and r.get("success"):
                python_successful += 1
                python_total_open += len(r.get("open_ports", []))

    python_time = time.time() - start_time
    python_rate = len(targets) / python_time

    print(f"   Time: {python_time:.3f}s")
    print(f"   Rate: {python_rate:.2f} scans/s")
    print(f"   Successful: {python_successful}/{len(targets)}")
    print(f"   Open ports found: {python_total_open}")

    results['python'] = {
        'time': python_time,
        'rate': python_rate,
        'successful': python_successful,
        'open_ports': python_total_open
    }

    speedup = python_time / rust_time
    print(f"\n{'=' * 80}")
    print(f"📊 RESULTS:")
    print(f"   Rust is {speedup:.2f}x faster than Python")
    print(f"   Time saved: {python_time - rust_time:.3f}s ({((python_time - rust_time) / python_time * 100):.1f}%)")
    print(f"{'=' * 80}")

    return results


async def run_full_benchmark(
        num_domains: int = 0,
        num_urls: int = 0,
        num_scans: int = 0,
        batch_size: int = 100
):
    """Run complete benchmark suite."""
    print("\n" + "=" * 80)
    print("🏁 NETWORK TOOL PERFORMANCE BENCHMARK")
    print("   Rust (via PyO3) vs Pure Python")
    print("=" * 80)

    print(f"\nTest Configuration:")
    if num_domains > 0:
        print(f"  - DNS Resolution: {num_domains:,} domains")
    if num_urls > 0:
        print(f"  - HTTP GET: {num_urls:,} URLs")
    if num_scans > 0:
        print(f"  - Port Scans: {num_scans:,} hosts (25 ports each)")
    print(f"  - Batch size: {batch_size}")

    all_results = {}

    # Run DNS benchmark if requested
    if num_domains > 0:
        print(f"\n📝 Generating {num_domains:,} test domains...")
        domains = generate_test_domains(num_domains)
        print(f"   ✓ Generated {len(domains)} domains")
        all_results['dns_resolve'] = await benchmark_dns_resolve(domains, batch_size)

    # Run HTTP benchmark if requested
    if num_urls > 0:
        print(f"\n📝 Generating {num_urls:,} test URLs...")
        urls = generate_test_urls(num_urls)
        print(f"   ✓ Generated {len(urls)} URLs")
        all_results['http_get'] = await benchmark_http_get(urls, min(batch_size, 20))

    # Run port scan benchmark if requested
    if num_scans > 0:
        print(f"\n📝 Generating {num_scans:,} port scan targets...")
        # Use scanme.nmap.org and localhost for testing
        hosts = ["scanme.nmap.org", "127.0.0.1"] * ((num_scans + 1) // 2)
        hosts = hosts[:num_scans]
        ports = generate_common_ports(25)
        targets = [(host, ports) for host in hosts]
        print(f"   ✓ Generated {len(targets)} scan targets")
        all_results['port_scan'] = await benchmark_port_scan(targets, min(batch_size, 10))

    # Summary
    if all_results:
        print("\n" + "=" * 80)
        print("📊 BENCHMARK SUMMARY")
        print("=" * 80)

        for test_name, results in all_results.items():
            print(f"\n{test_name.upper().replace('_', ' ')}:")
            if 'rust' in results:
                print(f"  Rust:   {results['rust']['time']:.3f}s ({results['rust']['rate']:.2f} req/s)")
            if 'python' in results:
                print(f"  Python: {results['python']['time']:.3f}s ({results['python']['rate']:.2f} req/s)")
                speedup = results['python']['time'] / results['rust']['time']
                print(f"  Speedup: {speedup:.2f}x")

        print("\n" + "=" * 80)
        print("🎉 Benchmark Complete!")
        print("=" * 80 + "\n")
    else:
        print("\n⚠️  No benchmarks specified. Use -d, -g, and/or -p flags.")
        print("=" * 80 + "\n")


async def interactive_mode():
    """Interactive benchmark mode."""
    print("\n" + "=" * 80)
    print("🏁 Network Tool Performance Benchmark")
    print("=" * 80)
    print("\nOptions:")
    print("  1. Quick benchmark (100 DNS + 100 HTTP + 10 port scans)")
    print("  2. Medium benchmark (1,000 DNS + 1,000 HTTP + 50 port scans)")
    print("  3. Large benchmark (10,000 DNS + 10,000 HTTP + 100 port scans)")
    print("  4. DNS only benchmark")
    print("  5. HTTP only benchmark")
    print("  6. Port scan only benchmark")
    print("  7. Custom benchmark")
    print("  8. Exit")
    print("=" * 80)

    choice = input("\nSelect an option (1-8): ").strip()

    if choice == "1":
        await run_full_benchmark(100, 100, 10, 100)
    elif choice == "2":
        await run_full_benchmark(1000, 1000, 50, 100)
    elif choice == "3":
        await run_full_benchmark(10000, 10000, 100, 200)
    elif choice == "4":
        try:
            count = int(input("Number of DNS requests: ").strip())
            batch = int(input("Batch size (default 100): ").strip() or "100")
            await run_full_benchmark(count, 0, 0, batch)
        except ValueError:
            print("Error: Invalid input")
    elif choice == "5":
        try:
            count = int(input("Number of HTTP requests: ").strip())
            batch = int(input("Batch size (default 20): ").strip() or "20")
            await run_full_benchmark(0, count, 0, batch)
        except ValueError:
            print("Error: Invalid input")
    elif choice == "6":
        try:
            count = int(input("Number of port scans: ").strip())
            batch = int(input("Batch size (default 10): ").strip() or "10")
            await run_full_benchmark(0, 0, count, batch)
        except ValueError:
            print("Error: Invalid input")
    elif choice == "7":
        try:
            dns_count = int(input("Number of DNS requests (0 to skip): ").strip() or "0")
            http_count = int(input("Number of HTTP requests (0 to skip): ").strip() or "0")
            scan_count = int(input("Number of port scans (0 to skip): ").strip() or "0")
            batch = int(input("Batch size (default 100): ").strip() or "100")
            await run_full_benchmark(dns_count, http_count, scan_count, batch)
        except ValueError:
            print("Error: Invalid input")
    elif choice == "8":
        print("\nGoodbye!")
        return
    else:
        print("\nInvalid option. Please select 1-8.")


async def main():
    """Main entry point."""
    import sys

    if len(sys.argv) > 1:
        # Parse command line arguments
        dns_count = 0
        http_count = 0
        scan_count = 0
        batch_size = 100

        i = 1
        while i < len(sys.argv):
            arg = sys.argv[i]

            if arg == "-d" and i + 1 < len(sys.argv):
                try:
                    dns_count = int(sys.argv[i + 1])
                    i += 2
                except ValueError:
                    print(f"Error: Invalid DNS count '{sys.argv[i + 1]}'")
                    return
            elif arg == "-g" and i + 1 < len(sys.argv):
                try:
                    http_count = int(sys.argv[i + 1])
                    i += 2
                except ValueError:
                    print(f"Error: Invalid HTTP count '{sys.argv[i + 1]}'")
                    return
            elif arg == "-p" and i + 1 < len(sys.argv):
                try:
                    scan_count = int(sys.argv[i + 1])
                    i += 2
                except ValueError:
                    print(f"Error: Invalid scan count '{sys.argv[i + 1]}'")
                    return
            elif arg == "-b" and i + 1 < len(sys.argv):
                try:
                    batch_size = int(sys.argv[i + 1])
                    i += 2
                except ValueError:
                    print(f"Error: Invalid batch size '{sys.argv[i + 1]}'")
                    return
            elif arg == "--quick":
                dns_count = 100
                http_count = 100
                scan_count = 10
                i += 1
            elif arg == "--medium":
                dns_count = 1000
                http_count = 1000
                scan_count = 50
                i += 1
            elif arg == "--large":
                dns_count = 10000
                http_count = 10000
                scan_count = 100
                i += 1
            elif arg == "--help" or arg == "-h":
                print("Usage:")
                print("  python benchmark.py                       # Interactive mode")
                print("  python benchmark.py -d <count>            # DNS benchmark only")
                print("  python benchmark.py -g <count>            # HTTP benchmark only")
                print("  python benchmark.py -p <count>            # Port scan benchmark only")
                print("  python benchmark.py -d <n> -g <n> -p <n>  # Combined benchmarks")
                print("  python benchmark.py -d 1000 -g 500 -b 100 # With custom batch size")
                print("\nPreset benchmarks:")
                print("  python benchmark.py --quick               # 100 DNS + 100 HTTP + 10 scans")
                print("  python benchmark.py --medium              # 1,000 DNS + 1,000 HTTP + 50 scans")
                print("  python benchmark.py --large               # 10,000 DNS + 10,000 HTTP + 100 scans")
                print("\nExamples:")
                print("  python benchmark.py -d 5000               # 5,000 DNS queries")
                print("  python benchmark.py -g 1000               # 1,000 HTTP requests")
                print("  python benchmark.py -p 50                 # 50 port scans")
                print("  python benchmark.py -d 10000 -g 5000 -p 100  # Combined")
                return
            else:
                print(f"Error: Unknown argument '{arg}'")
                print("Use --help for usage information")
                return

        if dns_count > 0 or http_count > 0 or scan_count > 0:
            await run_full_benchmark(dns_count, http_count, scan_count, batch_size)
        else:
            print("Error: No benchmark specified. Use -d, -g, and/or -p flags.")
            print("Use --help for usage information")
    else:
        await interactive_mode()


if __name__ == "__main__":
    asyncio.run(main())