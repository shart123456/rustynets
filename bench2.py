#!/usr/bin/env python3
"""
Interactive Port Scanner - User-friendly interface for netool
"""

import asyncio
import sys
import time
from typing import List
import netool


def parse_ip_list(ip_input: str) -> List[str]:
    """Parse comma-separated IP list and expand ranges."""
    ips = []

    for item in ip_input.split(','):
        item = item.strip()

        if '-' in item and item.count('.') == 3:
            # Handle IP ranges like 192.168.1.1-10
            try:
                base, range_part = item.rsplit('.', 1)
                if '-' in range_part:
                    start, end = range_part.split('-')
                    for i in range(int(start), int(end) + 1):
                        ips.append(f"{base}.{i}")
                else:
                    ips.append(item)
            except:
                ips.append(item)
        elif '/' in item:
            # CIDR notation (basic support for /24)
            if item.endswith('/24'):
                base = item.replace('/24', '').rsplit('.', 1)[0]
                ips.extend([f"{base}.{i}" for i in range(1, 255)])
            else:
                print(f"⚠️  Warning: Only /24 CIDR supported, skipping: {item}")
        else:
            # Regular IP or hostname
            ips.append(item)

    return ips


def parse_port_list(port_input: str) -> List[int]:
    """Parse port list with ranges and common presets."""

    # Presets
    presets = {
        'common': [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080],
        'web': [80, 443, 8000, 8080, 8443, 8888],
        'mail': [25, 110, 143, 465, 587, 993, 995],
        'database': [1433, 3306, 5432, 27017, 6379],
        'remote': [22, 23, 3389, 5900, 5901],
        'all': list(range(1, 65536)),
        'top100': [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 20, 69, 137, 138,
            161, 162, 389, 636, 989, 990, 1434, 2049, 2121, 3000, 5000, 5800, 8000,
            8888, 9000, 9090, 9999, 10000, 27017, 27018, 50000, 123, 179, 515, 631,
            873, 902, 1080, 1194, 1900, 2082, 2083, 2086, 2087, 2095, 2096, 3128,
            4444, 5555, 6379, 6666, 7777, 8001, 8008, 8009, 8081, 8082, 8083, 8089,
            8180, 9001, 9080, 9200, 9418, 10001, 11211, 50070, 62078
        ]
    }

    port_input = port_input.lower().strip()

    # Check for presets
    if port_input in presets:
        return presets[port_input]

    # Parse custom port list
    ports = []
    for item in port_input.split(','):
        item = item.strip()

        if '-' in item:
            # Range like 1-1000
            try:
                start, end = item.split('-')
                ports.extend(range(int(start), int(end) + 1))
            except:
                print(f"⚠️  Warning: Invalid port range '{item}', skipping")
        else:
            # Single port
            try:
                port = int(item)
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    print(f"⚠️  Warning: Port {port} out of range (1-65535)")
            except:
                print(f"⚠️  Warning: Invalid port '{item}', skipping")

    return sorted(list(set(ports)))  # Remove duplicates and sort


async def scan_single_host(host: str, ports: List[int], timeout: int, max_concurrent: int):
    """Scan a single host."""
    print(f"\n{'=' * 70}")
    print(f"Scanning: {host}")
    print(f"Ports: {len(ports)} ports")
    print(f"{'=' * 70}")

    start = time.time()
    result = await netool.port_scan(host, ports, timeout=timeout, max_concurrent=max_concurrent)
    elapsed = time.time() - start

    print(f"\n{'=' * 70}")
    print(f"Scan Results for {host}")
    print(f"{'=' * 70}")
    print(f"  Total ports scanned: {result['total_ports']:,}")
    print(f"  Open ports found: {len(result['open_ports'])}")
    print(f"  Closed ports: {result['closed_ports']:,}")
    print(f"  Scan time: {elapsed:.2f} seconds")
    print(f"  Scan rate: {result['total_ports'] / elapsed:.0f} ports/sec")

    if result['open_ports']:
        print(f"\n  🔓 Open Ports:")
        for port in sorted(set(result['open_ports'])):  # Remove duplicates
            print(f"     • {port}")
    else:
        print(f"\n  No open ports found")

    return result


async def scan_multiple_hosts(hosts: List[str], ports: List[int], timeout: int, max_concurrent: int, batch_size: int):
    """Scan multiple hosts."""
    print(f"\n{'=' * 70}")
    print(f"Scanning {len(hosts)} hosts with {len(ports)} ports each")
    print(f"Total port checks: {len(hosts) * len(ports):,}")
    print(f"Batch size: {batch_size}")
    print(f"{'=' * 70}\n")

    all_results = {}
    total_open = 0
    start = time.time()

    # Scan in batches to avoid overwhelming the system
    for i in range(0, len(hosts), batch_size):
        batch = hosts[i:i + batch_size]
        batch_num = i // batch_size + 1
        total_batches = (len(hosts) + batch_size - 1) // batch_size

        print(f"[Batch {batch_num}/{total_batches}] Scanning {len(batch)} hosts...")

        tasks = [
            netool.port_scan(host, ports, timeout=timeout, max_concurrent=max_concurrent)
            for host in batch
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for host, result in zip(batch, results):
            if isinstance(result, dict) and result.get('success'):
                open_ports = sorted(set(result['open_ports']))  # Remove duplicates
                if open_ports:
                    all_results[host] = open_ports
                    total_open += len(open_ports)
                    print(f"  [+] {host:20} -> {open_ports}")
            elif isinstance(result, Exception):
                print(f"  [-] {host:20} -> Error: {result}")

    elapsed = time.time() - start

    print(f"\n{'=' * 70}")
    print(f"Scan Complete")
    print(f"{'=' * 70}")
    print(f"  Total hosts scanned: {len(hosts)}")
    print(f"  Hosts with open ports: {len(all_results)}")
    print(f"  Total open ports found: {total_open}")
    print(f"  Total time: {elapsed:.2f} seconds")
    print(f"  Average per host: {elapsed / len(hosts):.3f} seconds")
    print(f"  Scan rate: {(len(hosts) * len(ports)) / elapsed:.0f} ports/sec")

    return all_results


async def interactive_mode():
    """Interactive mode for user input."""
    print("\n" + "=" * 70)
    print("🔍 INTERACTIVE PORT SCANNER")
    print("=" * 70)
    print("\nSupported IP formats:")
    print("  • Single IP: 192.168.1.1")
    print("  • Multiple IPs: 192.168.1.1, 192.168.1.5, 10.0.0.1")
    print("  • IP Range: 192.168.1.1-10 (scans .1 through .10)")
    print("  • CIDR /24: 192.168.1.0/24 (scans .1 through .254)")
    print("  • Hostnames: google.com, scanme.nmap.org")
    print("  • Mixed: 192.168.1.1-5, google.com, 10.0.0.1")

    print("\nSupported port formats:")
    print("  • Presets: common, web, mail, database, remote, top100, all")
    print("  • Single port: 80")
    print("  • Multiple ports: 22, 80, 443")
    print("  • Port range: 1-1000")
    print("  • Mixed: 22, 80, 443, 8000-8100")
    print("=" * 70)

    # Get IP input
    while True:
        ip_input = input("\n📍 Enter IP addresses (or 'q' to quit): ").strip()

        if ip_input.lower() in ['q', 'quit', 'exit']:
            print("\nGoodbye! 👋")
            return

        if not ip_input:
            print("❌ Error: Please enter at least one IP address")
            continue

        try:
            hosts = parse_ip_list(ip_input)
            if not hosts:
                print("❌ Error: No valid IP addresses parsed")
                continue

            print(f"✓ Parsed {len(hosts)} host(s): {hosts[:5]}" +
                  (f" ... and {len(hosts) - 5} more" if len(hosts) > 5 else ""))
            break
        except Exception as e:
            print(f"❌ Error parsing IPs: {e}")
            continue

    # Get port input
    while True:
        print("\nPort presets: common, web, mail, database, remote, top100, all")
        port_input = input("🔌 Enter ports (or preset name): ").strip()

        if not port_input:
            print("❌ Error: Please enter ports or a preset")
            continue

        try:
            ports = parse_port_list(port_input)
            if not ports:
                print("❌ Error: No valid ports parsed")
                continue

            if len(ports) > 1000:
                confirm = input(f"⚠️  You're scanning {len(ports)} ports. Continue? (y/n): ")
                if confirm.lower() != 'y':
                    continue

            print(f"✓ Parsed {len(ports)} port(s)" +
                  (f": {ports[:10]}..." if len(ports) > 10 else f": {ports}"))
            break
        except Exception as e:
            print(f"❌ Error parsing ports: {e}")
            continue

    # Advanced options
    print("\n⚙️  Advanced Options (press Enter for defaults)")

    timeout_input = input("⏱️  Timeout per port in seconds [2]: ").strip()
    timeout = int(timeout_input) if timeout_input else 2

    concurrent_input = input("🔀 Max concurrent connections [1000]: ").strip()
    max_concurrent = int(concurrent_input) if concurrent_input else 1000

    if len(hosts) > 1:
        batch_input = input(f"📦 Batch size for {len(hosts)} hosts [10]: ").strip()
        batch_size = int(batch_input) if batch_input else 10
    else:
        batch_size = 1

    # Confirm scan
    print(f"\n{'=' * 70}")
    print("🚀 Scan Configuration")
    print(f"{'=' * 70}")
    print(f"  Hosts: {len(hosts)}")
    print(f"  Ports per host: {len(ports)}")
    print(f"  Total port checks: {len(hosts) * len(ports):,}")
    print(f"  Timeout: {timeout}s")
    print(f"  Max concurrent: {max_concurrent}")
    if len(hosts) > 1:
        print(f"  Batch size: {batch_size}")
    print(f"{'=' * 70}")

    confirm = input("\nStart scan? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Scan cancelled.")
        return

    # Perform scan
    print("\n🔍 Starting scan...\n")

    try:
        if len(hosts) == 1:
            await scan_single_host(hosts[0], ports, timeout, max_concurrent)
        else:
            await scan_multiple_hosts(hosts, ports, timeout, max_concurrent, batch_size)
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error during scan: {e}")


async def cli_mode(args):
    """Command-line argument mode."""
    if '--help' in args or '-h' in args:
        print("""
Usage: python scanner.py [options]
       python scanner.py                    # Interactive mode

Options:
  -i, --ips <ips>              Comma-separated IP addresses
  -p, --ports <ports>          Comma-separated ports or preset
  -t, --timeout <seconds>      Timeout per port (default: 2)
  -c, --concurrent <number>    Max concurrent connections (default: 1000)
  -b, --batch <number>         Batch size for multiple hosts (default: 10)

Examples:
  python scanner.py -i 192.168.1.1 -p common
  python scanner.py -i 192.168.1.1-10 -p 80,443
  python scanner.py -i 192.168.1.0/24 -p top100
  python scanner.py -i google.com,github.com -p web
        """)
        return

    # Parse CLI arguments
    ips = None
    ports = None
    timeout = 2
    max_concurrent = 1000
    batch_size = 10

    i = 0
    while i < len(args):
        if args[i] in ['-i', '--ips'] and i + 1 < len(args):
            ips = args[i + 1]
            i += 2
        elif args[i] in ['-p', '--ports'] and i + 1 < len(args):
            ports = args[i + 1]
            i += 2
        elif args[i] in ['-t', '--timeout'] and i + 1 < len(args):
            timeout = int(args[i + 1])
            i += 2
        elif args[i] in ['-c', '--concurrent'] and i + 1 < len(args):
            max_concurrent = int(args[i + 1])
            i += 2
        elif args[i] in ['-b', '--batch'] and i + 1 < len(args):
            batch_size = int(args[i + 1])
            i += 2
        else:
            i += 1

    if not ips or not ports:
        print("❌ Error: Both --ips and --ports are required in CLI mode")
        print("Use --help for usage information")
        return

    hosts = parse_ip_list(ips)
    port_list = parse_port_list(ports)

    if not hosts or not port_list:
        print("❌ Error: Invalid IPs or ports")
        return

    print(f"Scanning {len(hosts)} host(s) with {len(port_list)} port(s)...")

    if len(hosts) == 1:
        await scan_single_host(hosts[0], port_list, timeout, max_concurrent)
    else:
        await scan_multiple_hosts(hosts, port_list, timeout, max_concurrent, batch_size)


async def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        await cli_mode(sys.argv[1:])
    else:
        await interactive_mode()


if __name__ == "__main__":
    asyncio.run(main())