#!/usr/bin/env python3
"""
Example Python script demonstrating how to use the netool Rust library
"""

import asyncio
import netool


async def main():
    print("=" * 60)
    print("Network Tool - Python Bindings Demo")
    print("=" * 60)

    # DNS Resolution
    print("\n1. DNS Resolution")
    print("-" * 60)
    result = await netool.dns_resolve("google.com")
    if result["success"]:
        print(f"Domain: {result['domain']}")
        print(f"IPs: {', '.join(result['ips'])}")
    else:
        print(f"Error: {result['error']}")

    # Reverse DNS Lookup
    print("\n2. Reverse DNS Lookup")
    print("-" * 60)
    result = await netool.dns_reverse("8.8.8.8")
    if result["success"]:
        print(f"IP: {result['ip']}")
        print(f"Names: {', '.join(result['names'])}")
    else:
        print(f"Error: {result['error']}")

    # Dig Query - A Record
    print("\n3. Dig Query - A Record")
    print("-" * 60)
    result = await netool.dig_query("example.com", "A")
    if result["success"]:
        print(f"Domain: {result['domain']}")
        print(f"Query Type: {result['query_type']}")
        print(f"Status: {result['status']}")
        print(f"Query Time: {result['query_time']}ms")
        print(f"Server: {result['server']}")
        print("Answers:")
        for answer in result['answers']:
            print(f"  {answer}")
    else:
        print(f"Error: {result['error']}")

    # Dig Query - MX Record
    print("\n4. Dig Query - MX Record")
    print("-" * 60)
    result = await netool.dig_query("gmail.com", "MX")
    if result["success"]:
        print(f"Domain: {result['domain']}")
        print(f"Query Type: {result['query_type']}")
        print("Answers:")
        for answer in result['answers']:
            print(f"  {answer}")
    else:
        print(f"Error: {result['error']}")

    # Dig Query - TXT Record
    print("\n5. Dig Query - TXT Record")
    print("-" * 60)
    result = await netool.dig_query("google.com", "TXT")
    if result["success"]:
        print(f"Domain: {result['domain']}")
        print("Answers:")
        for answer in result['answers']:
            print(f"  {answer}")
    else:
        print(f"Error: {result['error']}")

    # HTTP GET Request
    print("\n6. HTTP GET Request")
    print("-" * 60)
    result = await netool.http_get("https://example.com", timeout=10)
    if result["success"]:
        print(f"URL: {result['url']}")
        print(f"Status: {result['status']}")
        print(f"Content Length: {result['content_length']} bytes")
        print(f"Duration: {result['duration_ms']}ms")
    else:
        print(f"Error: {result['error']}")

    # Multiple DNS queries
    print("\n7. Multiple DNS Queries (Concurrent)")
    print("-" * 60)
    domains = ["google.com", "github.com", "rust-lang.org", "python.org"]

    tasks = [netool.dns_resolve(domain) for domain in domains]
    results = await asyncio.gather(*tasks)

    for result in results:
        if result["success"]:
            print(f"{result['domain']:20} -> {', '.join(result['ips'])}")
        else:
            print(f"{result['domain']:20} -> Error: {result['error']}")

    # Multiple HTTP requests
    print("\n8. Multiple HTTP Requests (Concurrent)")
    print("-" * 60)
    urls = [
        "https://example.com",
        "https://google.com",
        "https://github.com",
    ]

    tasks = [netool.http_get(url) for url in urls]
    results = await asyncio.gather(*tasks)

    for result in results:
        if result["success"]:
            print(f"{result['url']:30} -> Status: {result['status']}, Time: {result['duration_ms']}ms")
        else:
            print(f"{result['url']:30} -> Error: {result['error']}")

    print("\n" + "=" * 60)
    print("Demo Complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())