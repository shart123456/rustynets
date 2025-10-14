#!/usr/bin/env python3
"""
Web Fuzzing Test Script for netool
Similar to FlashFuzz functionality
"""

import asyncio
import netool
from datetime import datetime


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
║            Fast Web Fuzzer - Rust Powered                ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)


async def fuzz_directories_demo():
    """Demo: Directory/File Fuzzing"""
    print("\n" + "=" * 70)
    print("🔍 DIRECTORY FUZZING DEMO")
    print("=" * 70)

    target = "https://example.com"

    # Use built-in wordlist
    print(f"\n[*] Target: {target}")
    print("[*] Loading wordlist...")

    wordlist = netool.load_wordlist(None)  # None = use built-in
    print(f"[*] Loaded {len(wordlist)} words")

    print(f"[*] Starting fuzzing with 50 concurrent workers...")
    start_time = datetime.now()

    results = await netool.fuzz_directories(
        target,
        wordlist,
        max_concurrent=50,
        timeout=10,
        status_filter=[200, 301, 302, 403]  # Only show these status codes
    )

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Fuzzing completed in {duration:.2f} seconds")
    print(f"📊 Found {len(results)} interesting paths")

    if results:
        print(f"\n{'Status':<8} {'Size':<10} {'Time':<10} {'URL':<60}")
        print("-" * 90)

        for result in results[:20]:  # Show first 20
            status = result['status']
            size = result['content_length']
            time_ms = result['duration_ms']
            url = result['url']

            # Color code status
            if status == 200:
                status_str = f"✅ {status}"
            elif status in [301, 302]:
                status_str = f"↪️  {status}"
            elif status == 403:
                status_str = f"🔒 {status}"
            else:
                status_str = f"   {status}"

            print(f"{status_str:<8} {size:<10} {time_ms}ms {url:<60}"[:90])

        if len(results) > 20:
            print(f"\n... and {len(results) - 20} more results")


async def fuzz_subdomains_demo():
    """Demo: Subdomain Fuzzing"""
    print("\n" + "=" * 70)
    print("🌐 SUBDOMAIN FUZZING DEMO")
    print("=" * 70)

    domain = "example.com"

    # Custom subdomain wordlist
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
        timeout=5
    )

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print(f"\n✅ Subdomain fuzzing completed in {duration:.2f} seconds")
    print(f"📊 Found {len(results)} active subdomains")

    if results:
        print(f"\n{'Subdomain':<40} {'Status':<8} {'Size':<10}")
        print("-" * 60)

        for result in results:
            subdomain = result['url'].replace('https://', '').replace('http://', '')
            status = result['status']
            size = result['content_length']

            print(f"{subdomain:<40} {status:<8} {size:<10}")


async def fuzz_with_custom_wordlist():
    """Demo: Using custom wordlist from file"""
    print("\n" + "=" * 70)
    print("📄 CUSTOM WORDLIST DEMO")
    print("=" * 70)

    # Create a sample wordlist file
    print("\n[*] Creating sample wordlist...")
    with open('custom_wordlist.txt', 'w') as f:
        f.write("admin\n")
        f.write("login\n")
        f.write("dashboard\n")
        f.write("api\n")
        f.write("backup\n")
        f.write("config\n")
        f.write(".git\n")
        f.write(".env\n")

    print("[*] Loading custom wordlist from file...")
    wordlist = netool.load_wordlist("custom_wordlist.txt")
    print(f"[*] Loaded {len(wordlist)} words from file")

    target = "https://example.com"
    print(f"[*] Target: {target}")
    print(f"[*] Fuzzing...")

    results = await netool.fuzz_directories(
        target,
        wordlist,
        max_concurrent=10,
        timeout=10
    )

    print(f"\n✅ Found {len(results)} results")

    for result in results:
        print(f"  [{result['status']}] {result['url']}")

    # Cleanup
    import os
    os.remove('custom_wordlist.txt')
    print("\n[*] Cleaned up test file")


async def fuzz_with_extensions():
    """Demo: Fuzzing with file extensions"""
    print("\n" + "=" * 70)
    print("📎 EXTENSION FUZZING DEMO")
    print("=" * 70)

    target = "https://example.com"

    # Base words
    base_words = ["admin", "config", "backup", "test"]

    # Generate wordlist with extensions
    extensions = ["php", "html", "js", "json", "xml", "bak", "old", "zip"]
    wordlist = []

    for word in base_words:
        wordlist.append(word)  # Add base word
        for ext in extensions:
            wordlist.append(f"{word}.{ext}")  # Add with extension

    print(f"\n[*] Target: {target}")
    print(f"[*] Testing {len(base_words)} words with {len(extensions)} extensions")
    print(f"[*] Total paths to test: {len(wordlist)}")

    results = await netool.fuzz_directories(
        target,
        wordlist,
        max_concurrent=30,
        timeout=10,
        status_filter=[200, 403]  # Only show found or forbidden
    )

    print(f"\n✅ Found {len(results)} interesting files")

    for result in results:
        filename = result['url'].split('/')[-1]
        print(f"  [{result['status']}] {filename} ({result['content_length']} bytes)")


async def fuzz_comparison_test():
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
    results1 = await netool.fuzz_directories(target, wordlist, max_concurrent=1, timeout=10)
    time1 = (datetime.now() - start).total_seconds()
    print(f"      Completed in: {time1:.2f}s")

    # Test with 10 workers
    print(f"\n[2/3] Concurrent (10 workers)...")
    start = datetime.now()
    results2 = await netool.fuzz_directories(target, wordlist, max_concurrent=10, timeout=10)
    time2 = (datetime.now() - start).total_seconds()
    print(f"      Completed in: {time2:.2f}s")

    # Test with 50 workers
    print(f"\n[3/3] Concurrent (50 workers)...")
    start = datetime.now()
    results3 = await netool.fuzz_directories(target, wordlist, max_concurrent=50, timeout=10)
    time3 = (datetime.now() - start).total_seconds()
    print(f"      Completed in: {time3:.2f}s")

    print(f"\n📊 Performance Summary:")
    print(f"   Sequential:        {time1:.2f}s (baseline)")
    print(f"   10 workers:        {time2:.2f}s ({time1 / time2:.1f}x faster)")
    print(f"   50 workers:        {time3:.2f}s ({time1 / time3:.1f}x faster)")


async def main():
    """Main menu"""
    print_banner()

    print("\n" + "=" * 70)
    print("Select a demo:")
    print("  1. Directory/File Fuzzing")
    print("  2. Subdomain Fuzzing")
    print("  3. Custom Wordlist from File")
    print("  4. Extension Fuzzing")
    print("  5. Performance Comparison")
    print("  6. Run All Demos")
    print("=" * 70)

    choice = input("\nEnter choice (1-6): ").strip()

    if choice == '1':
        await fuzz_directories_demo()
    elif choice == '2':
        await fuzz_subdomains_demo()
    elif choice == '3':
        await fuzz_with_custom_wordlist()
    elif choice == '4':
        await fuzz_with_extensions()
    elif choice == '5':
        await fuzz_comparison_test()
    elif choice == '6':
        print("\n[*] Running all demos...")
        await fuzz_directories_demo()
        await fuzz_subdomains_demo()
        await fuzz_with_custom_wordlist()
        await fuzz_with_extensions()
        await fuzz_comparison_test()
        print("\n✅ All demos completed!")
    else:
        print("Invalid choice!")
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