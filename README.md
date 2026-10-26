# Cache Buster Finder

A small Python script for exploratory cache-behavior checks on a URL. It sends HTTP `GET` requests with common query parameters, selected request headers, and a few path variants, then prints response-based observations.

Use it only against PortSwigger Web Security Academy labs or systems you own or are explicitly authorized to test. It is an experimental helper, not a vulnerability scanner or proof that a cache key is configured correctly.

## Requirements

- Python 3
- `requests`

Install the dependency:

```bash
python3 -m pip install requests
```

## Usage

```bash
python3 cache.py --url 'https://YOUR-LAB-ID.web-security-academy.net/path'
```

Optional arguments:

```text
-p, --proxy     HTTP/S proxy URL, for example http://127.0.0.1:8080
-t, --timeout   Request timeout in seconds (default: 5)
```

For example, to send requests through a local intercepting proxy:

```bash
python3 cache.py \
  --url 'https://YOUR-LAB-ID.web-security-academy.net/path' \
  --proxy 'http://127.0.0.1:8080' \
  --timeout 10
```

The script does not follow redirects and verifies TLS certificates by default. The target must be supplied as a complete URL, including the scheme.

## What It Tests

- Sends two baseline `GET` requests and reports the second response's status and body length.
- Tries `cb`, `v`, `version`, and `id` query parameters together, using one random value.
- Sends one request for each header in `COMMON_HEADERS`; up to ten header requests may run concurrently.
- Requests path variants including a semicolon suffix, dot segment, repeated slash, parent segment, and encoded null byte.
- Looks for a limited set of cache response headers, primarily `X-Cache` and `CF-Cache-Status`.

## Reading the Results

Treat output as a lead to investigate manually, not a conclusion:

- A response length change can be caused by dynamic content, an error page, or other behavior unrelated to cache keys.
- A cache `MISS` can have causes other than the tested header or parameter.
- A path variant returning `200` only shows that the server returned that status; it does not establish cache-key behavior.
- The query parameters are tested as a group, so the script cannot identify which parameter influenced the response.
- Cache vendors use different status headers and values; a missing recognized header does not mean caching is absent.
- Concurrent requests can affect cache state and make comparisons less reliable.

For stronger evidence, compare repeat requests in the lab's browser or proxy, keep other request details constant, and confirm the behavior with the lab's intended workflow.

## Implementation Notes

The script currently sends `GET` requests only. `HTTP_METHODS` is declared but unused. TLS verification is enabled by default in the class, and the command-line interface does not expose custom request headers or a TLS verification flag.
