import argparse
import concurrent.futures
import random
import string
import sys
import time
from urllib.parse import urlparse
import requests

# Disable SSL warnings for testing environments
requests.packages.urllib3.disable_warnings()

# Configuration and Fuzzing Payloads
COMMON_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-For", "X-Host", "X-Forwarded-Scheme",
    "X-Original-URL", "X-Rewrite-URL", "True-Client-IP", "CF-Connecting-IP",
    "X-Client-IP", "X-Real-IP", "Max-Forwards", "Origin", "Via"
]

HTTP_METHODS = ["GET", "POST", "HEAD", "PURGE", "OPTIONS"]

def generate_random_string(length=8):
    """Generates a random alphanumeric string for cache busting."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

class CacheBusterFinder:
    def __init__(self, target_url, headers=None, proxy=None, timeout=5, verify=True):
        self.target_url = target_url
        self.base_headers = headers or {}
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.timeout = timeout
        self.verify = verify
        self.session = requests.Session()
        
        # Standardize modern browser user agent
        if "User-Agent" not in self.base_headers:
            self.base_headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def send_req(self, url, method="GET", headers=None, params=None):
        """Helper to safely handle HTTP requests."""
        try:
            req_headers = {**self.base_headers, **(headers or {})}
            resp = self.session.request(
                method=method,
                url=url,
                headers=req_headers,
                params=params,
                proxies=self.proxies,
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=False
            )
            return resp
        except Exception:
            return None

    def establish_baseline(self):
        """Analyzes how the target handles caching under normal circumstances."""
        print("[*] Establishing baseline response...")
        resp1 = self.send_req(self.target_url)
        if not resp1:
            print("[!] Critical: Target is unreachable.")
            return None
            
        # Sleep briefly to allow cache lookup/storage if needed
        time.sleep(0.5)
        resp2 = self.send_req(self.target_url)
        
        baseline = {
            "status_code": resp2.status_code,
            "content_length": len(resp2.content),
            "headers": resp2.headers
        }
        
        # Detect common cache status headers
        cache_indicators = ["X-Cache", "CF-Cache-Status", "X-Drupal-Cache", "X-Varnish", "Age"]
        found_indicators = [h for h in cache_indicators if h in resp2.headers]
        
        print(f"[+] Baseline set. Status: {baseline['status_code']} | Length: {baseline['content_length']} bytes")
        if found_indicators:
            print(f"[+] Cache headers detected: {', '.join([f'{h}: {resp2.headers[h]}' for h in found_indicators])}")
        return baseline

    def test_query_params(self, baseline):
        """Tests if common or unique query parameters act as cache keys."""
        print("[*] Testing query string behavior...")
        cb_val = generate_random_string()
        test_params = {"cb": cb_val, "v": cb_val, "version": cb_val, "id": cb_val}
        
        res = self.send_req(self.target_url, params=test_params)
        if res and "X-Cache" in res.headers:
            if "MISS" in res.headers["X-Cache"].upper() or "EXPIRED" in res.headers["X-Cache"].upper():
                return ("[+] SUCCESS: Standard query strings modify the cache key.", test_params)
        return ("[!] NOTICE: Standard query strings seem to be unkeyed/ignored.", None)

    def fuzz_headers(self, baseline):
        """Fuzzes standard HTTP headers concurrently to see if any are keyed."""
        print(f"[*] Fuzzing {len(COMMON_HEADERS)} potential header cache keys...")
        results = []

        def check_header(header_name):
            cb_val = generate_random_string()
            # Test 1: Random value
            resp = self.send_req(self.target_url, headers={header_name: cb_val})
            if resp:
                # Check for dynamic changes in length or explicit cache status change
                cache_header = next((resp.headers[h] for h in resp.headers if h.lower() == 'x-cache'), "")
                if "MISS" in cache_header.upper() or len(resp.content) != baseline["content_length"]:
                    return {"header": header_name, "value": cb_val, "type": "Dynamic Value Keyed"}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_header, h) for h in COMMON_HEADERS]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    results.append(res)
        return results

    def test_path_normalization(self):
        """Tests path manipulation strategies to find unkeyed path discrepancies."""
        print("[*] Testing path normalization and discrepancies...")
        parsed = urlparse(self.target_url)
        base_path = parsed.path if parsed.path else "/"
        
        # Common web server / cache alignment discrepancies
        paths_to_test = [
            f"{base_path};cb",
            f"{base_path}/.",
            f"{base_path}//",
            f"{base_path}/..{base_path}",
            f"{base_path}%00",
        ]
        
        valid_busters = []
        for path in paths_to_test:
            test_url = parsed._replace(path=path).geturl()
            resp = self.send_req(test_url)
            if resp and resp.status_code == 200:
                valid_busters.append(test_url)
        return valid_busters

    def run(self):
        baseline = self.establish_baseline()
        if not baseline:
            return

        print("\n" + "="*50 + "\n[!] SCANNING RESULTS\n" + "="*50)
        
        # 1. Test standard query parameters
        q_msg, q_data = self.test_query_params(baseline)
        print(q_msg)
        
        # 2. Test headers
        header_findings = self.fuzz_headers(baseline)
        if header_findings:
            print("[+] Found Keyed Headers:")
            for finding in header_findings:
                print(f"    -> {finding['header']}: Keyed trigger discovered via standard cache-miss conditions.")
        else:
            print("[-] No common headers acting as explicit cache busters detected.")

        # 3. Test path anomalies
        path_findings = self.test_path_normalization()
        if path_findings:
            print("[+] Path Normalization Cache Busters:")
            for url in path_findings:
                print(f"    -> Functional Variant: {url}")
        else:
            print("[-] Path transformation logic didn't yield uniform cache keys.")

def main():
    parser = argparse.ArgumentParser(description="Production Cache Buster Finder Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL endpoint to analyze")
    parser.add_argument("-p", "--proxy", help="HTTP/S proxy network path (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout duration in seconds")
    
    args = parser.parse_args()
    
    finder = CacheBusterFinder(target_url=args.url, proxy=args.proxy, timeout=args.timeout)
    finder.run()

if __name__ == "__main__":
    main()
