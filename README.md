# Byakugan — CDN Detector

> *"See the network like a true shinobi — spot the shadows behind domains."*

Byakugan is a fast, pragmatic CDN detection and CIDR checker. It looks for clues in DNS, HTTP headers, SSL issuers, IP ranges and organizational lookups to help you decide whether a host or IP range is served by a known CDN.

The project name and aesthetics are inspired by classic ninja lore — swift, observant, and a touch dramatic. Use it to inspect infrastructure, audit hosting, or teach networking & security concepts.

---

## ⚔️ What Byakugan does (quick)

* Detect whether a domain or IP is behind a known CDN using multiple signals (CNAMEs, HTTP headers, SSL issuer, IP ranges).
* Parse and fetch CDN-provider IP ranges from provider URLs and cache them for fast lookups.
* Check if a CIDR overlaps with any known CDN ranges.
* Export results as pretty console output or JSON for automation.

---

## 🔥 Features

* Multi-signal detection: DNS, HTTP headers, SSL issuer, ASN/org lookups, and range overlap checks.
* Robust CIDR and IP extraction from raw text and JSON feeds.
* Concurrent fetching of provider ranges with a configurable worker pool.
* Cache of fetched ranges with TTL to avoid repeated downloads.
* JSON output and export for pipelines and integration.

---

## 🛠️ Installation

```bash
# Recommended: create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

`requirements.txt` should include at minimum:

* `requests`
* `dnspython`
* `colorama`

(There are optional dependencies used for extended tooling in the repo — see `requirements.txt` for extras.)

---

## ⚡ Usage

```bash
# Analyze a domain
python3 byakugan.py example.com

# Analyze an IP
python3 byakugan.py 1.2.3.4

# Check a CIDR for overlaps with known CDN ranges
python3 byakugan.py 151.101.0.0/16

# Update cached CDN ranges (fetch from provider sources)
python3 byakugan.py --update

# List CDNs defined in your CDN-DB.json
python3 byakugan.py --list-cdns

# JSON output
python3 byakugan.py example.com --format json --export-json result.json
```

---

## 🧭 CDN-DB.json (how to define providers)

The tool reads a `CDN-DB.json` containing provider metadata. Example provider entry shape:

```json
{
  "providers": {
    "cloudflare": {
      "name": "Cloudflare",
      "range_urls": [
        "https://api.cloudflare.com/.../ips"
      ],
      "asns": ["13335"],
      "cname_tokens": ["cloudflare"],
      "header_tokens": ["server", "cf-ray"],
      "issuer_tokens": ["cloudflare"],
      "org_tokens": ["cloudflare"]
    }
  }
}
```

* `range_urls`: list of HTTP(S) endpoints that publish provider IP ranges (JSON or newline-delimited text). The fetcher will attempt JSON parsing and also run a regex extractor for CIDRs.
* `asns`: optional ASN list to query as a fallback (via BGPView).
* `*_tokens`: small token lists to match against CNAMEs, headers, SSL issuers, and org strings.

---

## 🧪 Examples

* Quick check: `python3 byakugan.py example.com`
* Script-friendly: `python3 byakugan.py example.com --format json --export-json out.json`
* Refresh ranges before a big audit: `python3 byakugan.py --update`

---

## 👥 Contributing

Contributions are welcome. Typical ways to help:

* Add or improve provider definitions in `CDN-DB.json`.
* Improve parsers for provider JSON shapes.
* Add unit tests for CIDR extraction, overlap checks, and detection heuristics.
* Improve docs and examples.

If you open a PR, include tests or a short explanation of the change. Keep changes focused — like a well-placed kunai.

---

## 📝 License

This repository is provided under the MIT License. See `LICENSE` for details.

---

## 🙏 Notes & ethics

This tool is designed for network analysis, auditing, research and education. Do not use it to perform unauthorized scanning or attack infrastructure. Act like a responsible shinobi: observe, report, and respect boundaries.

---

If you want, I can now:

* generate a sample `CDN-DB.json` with a few popular providers,
* produce a `LICENSE` (MIT),
* make a polished `requirements.txt`, or
* create a GitHub-ready repo layout with GH Actions for linting and tests.

Which one should I craft next, little shadow? 🥷
