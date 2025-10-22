#!/usr/bin/env python3
"""
Enhanced Web Fuzzing Test Script for netool
Demonstrates all fuzzing capabilities including parameter fuzzing and permutations
"""

import asyncio
import netool
from datetime import datetime
import os


def print_banner():
    """Print cool banner"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ███████╗██╗      █████╗ ███████╗██╗  ██╗              ║
║   ██╔════╝██║     ██╔══██╗██╔════╝██║  ██║              ║
║   █████╗  ██║     ███████║███████╗███████║              ║
║   ██╔══╝  ██║     ██╔══██║╚════██║██╔══██║              ║
║   ██║     ███████╗██║  ██║███████║██║  ██║              ║
║   ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝              ║
║                                                           ║
║   ███████╗██╗   ██╗███████╗███████╗                     ║
║   ██╔════╝██║   ██║╚══███╔╝╚══███╔╝                     ║
║   █████╗  ██║   ██║  ███╔╝   ███╔╝                      ║
║   ██╔══╝  ██║   ██║ ███╔╝   ███╔╝                       ║
║   ██║     ╚██████╔╝███████╗███████╗                     ║
║   ╚═╝      ╚═════╝ ╚══════╝╚══════╝                     ║
║                                                           ║
║         Fast Web Fuzzer - Rust Powered v2.0              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)


def format_result(result):
    """Format a fuzz result for display"""
    status = result.get('status_code', 0)
    size = result.get('content_length', 0)
    time_ms = result.get('duration_ms', 0)
    url = result.get('url', '')
    error = result.get('error')

    # Color code status
    if error:
        status_str = f"❌ ERR"
    elif status == 200:
        status_str = f"✅ {status}"
    elif status in [301, 302, 307, 308]:
        status_str = f"↪️  {status}"
    elif status == 403:
        status_str = f"🔒 {status}"
    elif status == 401:
        status_str = f"🔑 {status}"
    elif status == 404:
        status_str = f"❌ {status}"
    elif status >= 500:
        status_str = f"💥 {status}"
    else:
        status_str = f"   {status}"

    return status_str, size, time_ms, url, error


async def fuzz_directories_demo():
    """Demo: Directory/File Fuzzing"""
    print("\n" + "=" * 70)
    print("🔍 DIRECTORY FUZZING DEMO")
    print("=" * 70)

    target = "https://example.com"

    print(f"\n[*] Target: {target}")
    print("[*] Loading built-in wordlist...")

    wordlist = netool.load_wordlist(None)  # None = use built-in
    print(f"[*] Loaded {len(wordlist)} words")

    print(f"[*] Starting fuzzing with 50 concurrent workers...")
    start_time = datetime.now()

    results = await netool.fuzz_directories(
        target,
        wordlist,
        max_concurrent=50,
        timeout=10,
        status_filter=[200, 301, 302, 403],
        show_errors=False
    )

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Fuzzing completed in {duration:.2f} seconds")
    print(f"📊 Found {len(results)} interesting paths")

    if results:
        print(f"\n{'Status':<10} {'Size':<12} {'Time':<12} {'URL':<50}")
        print("-" * 90)

        for result in results[:20]:
            status_str, size, time_ms, url, error = format_result(result)
            print(f"{status_str:<10} {size:<12} {time_ms}ms{'':<8} {url[:50]}")

        if len(results) > 20:
            print(f"\n... and {len(results) - 20} more results")


async def fuzz_subdomains_demo():
    """Demo: Subdomain Fuzzing"""
    print("\n" + "=" * 70)
    print("🌐 SUBDOMAIN FUZZING DEMO")
    print("=" * 70)

    domain = "example.com"

    wordlist = [
        "www", "api", "dev", "staging", "test",
        "admin", "mail", "ftp", "blog", "shop",
        "portal", "dashboard", "app", "mobile",
        "cdn", "static", "assets", "media"
    ]

    print(f"\n[*] Target domain: {domain}")
    print(f"[*] Testing {len(wordlist)} subdomains...")

    start_time = datetime.now()

    results = await netool.fuzz_subdomains(
        domain,
        wordlist,
        max_concurrent=20,
        timeout=5,
        show_errors=False
    )

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Subdomain fuzzing completed in {duration:.2f} seconds")
    print(f"📊 Found {len(results)} active subdomains")

    if results:
        print(f"\n{'Subdomain':<40} {'Status':<10} {'Size':<12}")
        print("-" * 65)

        for result in results:
            subdomain = result['url'].replace('https://', '').replace('http://', '').split('/')[0]
            status_str, size, _, _, _ = format_result(result)
            print(f"{subdomain:<40} {status_str:<10} {size:<12}")


async def fuzz_with_backup_files():
    """Demo: Fuzzing for backup files using common extensions"""
    print("\n" + "=" * 70)
    print("💾 BACKUP FILE FUZZING DEMO")
    print("=" * 70)

    target = "https://example.com"

    # Base files to check
    base_files = ["config", "database", "backup", "admin", "index", "app"]

    print(f"\n[*] Target: {target}")
    print(f"[*] Generating backup file wordlist...")

    # Get common backup extensions
    backup_extensions = netool.get_common_file_extensions()
    print(f"[*] Using {len(backup_extensions)} backup extensions")

    # Generate permutations
    wordlist = netool.generate_permutations(base_files, backup_extensions, max_depth=2)
    print(f"[*] Generated {len(wordlist)} permutations")
    print(f"[*] Examples: {', '.join(wordlist[:5])}...")

    print(f"\n[*] Starting fuzzing...")
    start_time = datetime.now()

    results = await netool.fuzz_directories(
        target,
        wordlist,
        max_concurrent=50,
        timeout=10,
        status_filter=[200, 403],  # Found or forbidden
        show_errors=False
    )

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Fuzzing completed in {duration:.2f} seconds")
    print(f"🔍 Found {len(results)} potential backup files")

    if results:
        print(f"\n{'Status':<10} {'Size':<12} {'Filename':<50}")
        print("-" * 75)

        for result in results[:20]:
            status_str, size, _, url, _ = format_result(result)
            filename = url.split('/')[-1]
            print(f"{status_str:<10} {size:<12} {filename:<50}")


async def fuzz_sensitive_files():
    """Demo: Fuzzing for sensitive files"""
    print("\n" + "=" * 70)
    print("🔐 SENSITIVE FILE DISCOVERY DEMO")
    print("=" * 70)

    target = "https://example.com"

    print(f"\n[*] Target: {target}")
    print("[*] Loading sensitive file patterns...")

    # Get common backup patterns
    wordlist = netool.get_backup_file_patterns()
    print(f"[*] Testing {len(wordlist)} sensitive file patterns")
    print(f"[*] Examples: {', '.join(wordlist[:5])}...")

    print(f"\n[*] Starting fuzzing...")
    start_time = datetime.now()

    results = await netool.fuzz_directories(
        target,
        wordlist,
        max_concurrent=30,
        timeout=10,
        status_filter=[200, 403],
        show_errors=False
    )

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Fuzzing completed in {duration:.2f} seconds")
    print(f"⚠️  Found {len(results)} sensitive files")

    if results:
        print(f"\n{'Status':<10} {'Size':<12} {'File':<50}")
        print("-" * 75)

        for result in results:
            status_str, size, _, url, _ = format_result(result)
            filename = url.split('/')[-1]

            # Highlight dangerous files
            if any(danger in filename for danger in ['.env', '.git', 'config', 'database', 'wp-config']):
                print(f"{status_str:<10} {size:<12} 🚨 {filename:<50}")
            else:
                print(f"{status_str:<10} {size:<12} {filename:<50}")


async def fuzz_parameters_demo():
    """Demo: Parameter fuzzing"""
    print("\n" + "=" * 70)
    print("🎯 PARAMETER FUZZING DEMO")
    print("=" * 70)

    base_url = "https://example.com/search"

    print(f"\n[*] Target: {base_url}")
    print("[*] Loading common parameters...")

    # Get common parameters
    parameters = netool.get_common_parameters()
    print(f"[*] Testing {len(parameters)} parameters")
    print(f"[*] Examples: {', '.join(parameters[:10])}...")

    # Get common payloads
    payloads = ["test", "1", "admin", "../", "' OR '1'='1"]
    print(f"\n[*] Using {len(payloads)} test payloads")

    print(f"[*] Total combinations: {len(parameters) * len(payloads)}")
    print(f"[*] Starting fuzzing...")

    start_time = datetime.now()

    results = await netool.fuzz_parameters(
        base_url,
        parameters,
        payloads,
        max_concurrent=50,
        timeout=10,
        show_errors=False
    )

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Fuzzing completed in {duration:.2f} seconds")
    print(f"📊 Found {len(results)} interesting responses")

    if results:
        print(f"\n{'Status':<10} {'Size':<12} {'URL':<60}")
        print("-" * 85)

        for result in results[:20]:
            status_str, size, _, url, _ = format_result(result)
            # Shorten URL for display
            display_url = url if len(url) <= 60 else url[:57] + "..."
            print(f"{status_str:<10} {size:<12} {display_url}")


async def fuzz_parameter_values_demo():
    """Demo: Fuzzing existing parameter values"""
    print("\n" + "=" * 70)
    print("🔄 PARAMETER VALUE FUZZING DEMO")
    print("=" * 70)

    # URL with existing parameters
    target_url = "https://example.com/page?id=1&file=test.php"

    print(f"\n[*] Target: {target_url}")
    print("[*] Loading attack payloads...")

    # Get common attack payloads
    payloads = netool.get_common_payloads()
    print(f"[*] Testing {len(payloads)} payloads")
    print(f"[*] Payload types: Path Traversal, LFI, RFI, SQLi, XSS, SSRF")

    print(f"\n[*] Starting fuzzing...")
    start_time = datetime.now()

    results = await netool.fuzz_parameter_values(
        target_url,
        payloads,
        max_concurrent=30,
        timeout=10,
        show_errors=False
    )

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Fuzzing completed in {duration:.2f} seconds")
    print(f"🎯 Tested {len(payloads)} payloads on each parameter")
    print(f"📊 Found {len(results)} interesting responses")

    if results:
        print(f"\n{'Status':<10} {'Size':<12} {'URL':<60}")
        print("-" * 85)

        # Group by status code
        status_groups = {}
        for result in results:
            status = result.get('status_code', 0)
            if status not in status_groups:
                status_groups[status] = []
            status_groups[status].append(result)

        # Show results grouped by status
        for status in sorted(status_groups.keys()):
            print(f"\n--- Status {status} ({len(status_groups[status])} results) ---")
            for result in status_groups[status][:5]:
                status_str, size, _, url, _ = format_result(result)
                display_url = url if len(url) <= 60 else url[:57] + "..."
                print(f"{status_str:<10} {size:<12} {display_url}")


async def fuzz_with_permutations():
    """Demo: Advanced permutation generation"""
    print("\n" + "=" * 70)
    print("🔀 PERMUTATION FUZZING DEMO")
    print("=" * 70)

    target = "https://example.com"

    print(f"\n[*] Target: {target}")
    print("[*] Generating advanced permutations...")

    # Base files
    base_files = ["admin", "config", "backup"]

    # Generate with multiple extension layers
    extensions = ["php", "bak", "old", "zip", "txt"]

    print(f"\n[1/3] Generating permutations...")
    wordlist = netool.generate_permutations(base_files, extensions, max_depth=3)
    print(f"        Created {len(wordlist)} variations")
    print(f"        Examples: {', '.join(wordlist[:5])}...")

    # Add case variations
    print(f"\n[2/3] Adding case variations...")
    original_count = len(wordlist)
    case_wordlist = []
    for word in base_files:
        case_wordlist.extend(netool.generate_case_variations(word))
    wordlist.extend(case_wordlist)
    print(f"        Added {len(wordlist) - original_count} case variations")

    # Add numbered variations
    print(f"\n[3/3] Adding numbered variations...")
    original_count = len(wordlist)
    numbered = netool.generate_numbered_variations(base_files, 1, 5)
    wordlist.extend(numbered)
    print(f"        Added {len(wordlist) - original_count} numbered variations")

    print(f"\n[*] Total wordlist size: {len(wordlist)}")
    print(f"[*] Starting fuzzing...")

    start_time = datetime.now()

    results = await netool.fuzz_directories(
        target,
        wordlist,
        max_concurrent=50,
        timeout=10,
        status_filter=[200, 403],
        show_errors=False
    )

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Fuzzing completed in {duration:.2f} seconds")
    print(f"📊 Found {len(results)} files")

    if results:
        print(f"\n{'Status':<10} {'Size':<12} {'Filename':<50}")
        print("-" * 75)

        for result in results[:15]:
            status_str, size, _, url, _ = format_result(result)
            filename = url.split('/')[-1]
            print(f"{status_str:<10} {size:<12} {filename:<50}")


async def fuzz_word_combinations():
    """Demo: Combining words with separators"""
    print("\n" + "=" * 70)
    print("🔗 WORD COMBINATION DEMO")
    print("=" * 70)

    target = "https://example.com"

    print(f"\n[*] Target: {target}")
    print("[*] Generating word combinations...")

    # Base words to combine
    words = ["admin", "panel", "user", "login", "dashboard", "control"]

    # Combine with different separators
    separators = ["-", "_", ""]

    wordlist = netool.combine_words(words, separators)
    print(f"[*] Generated {len(wordlist)} combinations")
    print(f"[*] Examples: {', '.join(wordlist[:10])}...")

    print(f"\n[*] Starting fuzzing...")
    start_time = datetime.now()

    results = await netool.fuzz_directories(
        target,
        wordlist,
        max_concurrent=50,
        timeout=10,
        status_filter=[200, 301, 302, 403],
        show_errors=False
    )

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Fuzzing completed in {duration:.2f} seconds")
    print(f"📊 Found {len(results)} paths")

    if results:
        print(f"\n{'Status':<10} {'Size':<12} {'Path':<50}")
        print("-" * 75)

        for result in results[:15]:
            status_str, size, _, url, _ = format_result(result)
            path = url.split('/')[-1]
            print(f"{status_str:<10} {size:<12} {path:<50}")


async def fuzz_with_custom_wordlist():
    """Demo: Using custom wordlist from file"""
    print("\n" + "=" * 70)
    print("📄 CUSTOM WORDLIST DEMO")
    print("=" * 70)

    print("\n[*] Creating sample wordlist file...")
    with open('custom_wordlist.txt', 'w') as f:
        f.write("# Custom wordlist for fuzzing\n")
        f.write("admin\n")
        f.write("login\n")
        f.write("dashboard\n")
        f.write("api\n")
        f.write("backup\n")
        f.write("config\n")
        f.write(".git\n")
        f.write(".env\n")
        f.write("# End of wordlist\n")

    print("[*] Loading custom wordlist from file...")
    wordlist = netool.load_wordlist("custom_wordlist.txt")
    print(f"[*] Loaded {len(wordlist)} words (comments ignored)")

    target = "https://example.com"
    print(f"[*] Target: {target}")
    print(f"[*] Fuzzing...")

    results = await netool.fuzz_directories(
        target,
        wordlist,
        max_concurrent=10,
        timeout=10,
        show_errors=False
    )

    print(f"\n✅ Found {len(results)} results")

    if results:
        print(f"\n{'Status':<10} {'Size':<12} {'URL':<50}")
        print("-" * 75)
        for result in results:
            status_str, size, _, url, _ = format_result(result)
            print(f"{status_str:<10} {size:<12} {url:<50}")

    # Cleanup
    os.remove('custom_wordlist.txt')
    print("\n[*] Cleaned up test file")


async def fuzz_performance_comparison():
    """Compare sequential vs concurrent fuzzing"""
    print("\n" + "=" * 70)
    print("⚡ PERFORMANCE COMPARISON")
    print("=" * 70)

    target = "https://example.com"
    wordlist = ["admin", "login", "api", "test", "backup",
                "config", "dashboard", "assets", "static", "uploads"]

    print(f"\n[*] Target: {target}")
    print(f"[*] Wordlist size: {len(wordlist)} paths")

    # Test with 1 worker (sequential)
    print(f"\n[1/3] Sequential (1 worker)...")
    start = datetime.now()
    results1 = await netool.fuzz_directories(
        target, wordlist, max_concurrent=1, timeout=10, show_errors=False
    )
    time1 = (datetime.now() - start).total_seconds()
    print(f"      Completed in: {time1:.2f}s - Found: {len(results1)} results")

    # Test with 10 workers
    print(f"\n[2/3] Concurrent (10 workers)...")
    start = datetime.now()
    results2 = await netool.fuzz_directories(
        target, wordlist, max_concurrent=10, timeout=10, show_errors=False
    )
    time2 = (datetime.now() - start).total_seconds()
    print(f"      Completed in: {time2:.2f}s - Found: {len(results2)} results")

    # Test with 50 workers
    print(f"\n[3/3] Concurrent (50 workers)...")
    start = datetime.now()
    results3 = await netool.fuzz_directories(
        target, wordlist, max_concurrent=50, timeout=10, show_errors=False
    )
    time3 = (datetime.now() - start).total_seconds()
    print(f"      Completed in: {time3:.2f}s - Found: {len(results3)} results")

    print(f"\n📊 Performance Summary:")
    print(f"   Sequential (1):     {time1:.2f}s (baseline)")
    if time2 > 0:
        print(f"   Concurrent (10):    {time2:.2f}s ({time1 / time2:.1f}x faster)")
    if time3 > 0:
        print(f"   Concurrent (50):    {time3:.2f}s ({time1 / time3:.1f}x faster)")


async def main():
    """Main menu"""
    print_banner()

    demos = {
        '1': ('Directory/File Fuzzing', fuzz_directories_demo),
        '2': ('Subdomain Fuzzing', fuzz_subdomains_demo),
        '3': ('Backup File Discovery', fuzz_with_backup_files),
        '4': ('Sensitive File Discovery', fuzz_sensitive_files),
        '5': ('Parameter Fuzzing', fuzz_parameters_demo),
        '6': ('Parameter Value Fuzzing', fuzz_parameter_values_demo),
        '7': ('Permutation Fuzzing', fuzz_with_permutations),
        '8': ('Word Combination Fuzzing', fuzz_word_combinations),
        '9': ('Custom Wordlist', fuzz_with_custom_wordlist),
        '10': ('Performance Comparison', fuzz_performance_comparison),
        '11': ('Run All Demos', None),
    }

    print("\n" + "=" * 70)
    print("Select a demo:")
    for key, (name, _) in demos.items():
        print(f"  {key:>2}. {name}")
    print("=" * 70)

    choice = input("\nEnter choice (1-11): ").strip()

    if choice == '11':
        print("\n[*] Running all demos...")
        for key, (name, func) in demos.items():
            if func:  # Skip the "Run All" option itself
                print(f"\n{'=' * 70}")
                print(f"Running: {name}")
                print(f"{'=' * 70}")
                try:
                    await func()
                except Exception as e:
                    print(f"❌ Error in {name}: {e}")
                await asyncio.sleep(1)  # Brief pause between demos
        print("\n✅ All demos completed!")
    elif choice in demos and demos[choice][1]:
        await demos[choice][1]()
    else:
        print("❌ Invalid choice!")
        return

    print("\n" + "=" * 70)
    print("✅ DEMO COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()