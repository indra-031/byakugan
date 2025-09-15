#!/usr/bin/env python3

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import ssl
import socket
import sys
import time
from typing import Dict, List, Optional, Tuple, Set

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import dns.resolver
    from colorama import Fore, Style, init as colorama_init
except Exception:
    print("Missing dependencies. Run: pip install requests dnspython colorama urllib3")
    raise

colorama_init(autoreset=True)

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(HERE, "CDN-DB.json")
CACHE_DIR = os.path.expanduser("~/.byakugan")
CACHE_FILE = os.path.join(CACHE_DIR, "ranges.json")
DEFAULT_CACHE_TTL = 24 * 3600  # 1 day

ASCII = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢢⠀⠀⠀⢢⠀⢦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡀⠀⢣⡀⠀⠀⠀⢣⢀⠀⠘⡆⢸⡀⠀⢢⠀⠀⠀⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢄⠑⣄⠀⢻⠀⠀⠀⠘⡌⡆⠀⡇⢸⡇⠀⢸⡀⡆⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⠼⣷⠼⡦⣼⣯⣧⣀⢰⡇⡇⢰⠇⣼⢳⠀⢸⡇⡇⠀⢸⡇⠀⡄⠀⢰⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣶⠿⠛⢉⡈⢧⡀⣸⡆⣇⣿⠃⣿⢀⣿⣻⢷⣿⣴⣇⡿⢀⣾⢠⡇⢀⣿⠀⢰⠃⠀⡜⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⡿⠋⢡⡀⠙⣦⠹⣎⣧⣿⣿⣿⣿⣼⣿⣿⣿⣿⣿⣾⣿⣿⣳⣿⣧⡿⣠⣾⡿⢀⢎⠀⡼⢁⠂⠀⡐⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⠟⠉⠀⠀⢠⠹⣿⣾⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣵⡷⣫⣾⠞⣡⠏⣠⡞⠀⣠⡆
⠀⠀⠀⠀⠀⣠⡿⠋⠀⠀⠠⣱⣄⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣾⣷⣾⣯⣶⣿⡿⠃
⠀⠀⠀⠀⣴⠟⠁⠀⢤⡱⣄⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⣿⣿⡿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠉⠀⠀
⠀⠀⠀⣼⠋⠀⠀⣝⢦⣿⣿⣿⣿⣿⣿⣿⠿⢿⣿⣿⣿⣿⣷⣂⡙⣿⣿⡇⠀⠀⠀⠀⠀⠈⢉⣿⣿⣿⣿⣿⣿⠿⢿⣄⠀⠀⠀⠀⠀
⠀⠀⣼⠃⠀⠀⠤⣬⣿⣿⣿⣿⣿⡉⣿⣿⣄⣼⣿⣿⣿⣿⡟⠉⠀⢿⣿⡿⠀⠀⠀⠀⠀⢠⣾⣿⠿⠿⠿⠿⣟⡳⠄⠉⠀⠀⠀⠀⠀
⠀⣸⠃⠀⠀⢀⣾⣿⣿⠟⠋⢿⣥⡬⠙⣿⣿⣿⣿⣿⣿⡧⠀⠀⢲⣄⣿⠇⠀⠀⠀⢀⣴⣿⣿⣿⡿⣛⣓⠲⢤⡉⠀⠀⠀⠀⠀⠀⠀
⢰⠃⠀⠀⣠⣿⣿⠟⠁⠀⠀⠘⢿⣔⣢⡴⠛⠙⠛⠛⢁⠀⢠⣾⣦⣿⠏⠀⠀⢀⣴⣿⣿⣿⣯⡭⢍⡒⢌⠙⠦⡈⢢⡀⠀⠀⠀⠀⠀
⠁⠀⠀⣰⣿⡿⠁⠀⠀⠀⠀⠀⠈⠛⢿⣿⣿⣄⣴⣷⣾⣷⣤⣿⠟⠁⠀⣠⣴⣿⣿⣿⣿⣾⣍⡻⡄⠈⠳⡅⠀⠈⠂⠀⠀⠀⠀⠀⠀
⠀⠀⣼⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠛⠉⠉⣀⣠⣶⣿⣿⣿⣿⣿⡿⢿⣿⣮⠙⢦⠀⠀⠈⠆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣸⠟⠁⠀⢀⣠⣤⣶⡶⢶⣶⣶⣦⣤⣤⣤⣤⣤⣶⣶⣾⣿⣿⣿⡿⢿⡿⣝⢫⡻⣍⠳⣝⢻⢧⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣰⠋⢀⣴⠞⠋⠉⠠⠋⠠⢋⠞⣹⢻⠏⢸⠉⡏⡿⢹⢿⢻⣿⢿⣿⡿⣦⠹⡈⠳⡘⡈⢣⠘⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠈⠀⠃⠀⠀⠘⠀⠀⡇⡜⠈⡸⢸⠀⢹⢸⠈⢆⠁⠀⢱⠁⠀⢇⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠘⠀⠘⠀⠀⢸⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

        Byakugan — CDN detector 
"""

# Regexes
CIDR_V4_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})){3}/(?:[0-9]|[1-2][0-9]|3[0-2])\b"
)
CIDR_V6_RE = re.compile(r"\b(?:[0-9a-fA-F:]{2,})(?:/[0-9]{1,3})\b")
IP_V4_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})){3}\b"
)
IP_RANGE_RE = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})\s*-\s*((?:\d{1,3}\.){3}\d{1,3})\b"
)  # 1.2.3.4 - 1.2.3.255

# HTTP session with retry/backoff
def make_session(retries: int = 3, backoff: float = 0.3, timeout: int = 8) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "HEAD", "OPTIONS"]),
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": "Byakugan/1.0"})
    s.request_timeout = timeout  # custom attribute used by wrappers
    return s


# Colored printing helpers
def info(msg: str, quiet: bool = False):
    if not quiet:
        print(Fore.CYAN + "[i] " + Style.RESET_ALL + msg)


def ok(msg: str, quiet: bool = False):
    if not quiet:
        print(Fore.GREEN + "+ " + Style.RESET_ALL + msg)


def warn(msg: str, quiet: bool = False):
    if not quiet:
        print(Fore.YELLOW + "[!] " + Style.RESET_ALL + msg)


def err(msg: str, quiet: bool = False):
    if not quiet:
        print(Fore.RED + "[-] " + Style.RESET_ALL + msg)


# Load CDN DB
def load_cdn_db(path: Optional[str]) -> Dict:
    path = path or DEFAULT_DB
    if not os.path.exists(path):
        raise FileNotFoundError(f"CDN DB not found: {path}. Create or pass --db <path>")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Extract CIDRs and single IPs from text
def extract_cidrs(text: str) -> List[str]:
    cidrs: Set[str] = set()
    if not text:
        return []
    for m in CIDR_V4_RE.findall(text):
        try:
            ipaddress.ip_network(m, strict=False)
            cidrs.add(m)
        except Exception:
            pass
    for m in CIDR_V6_RE.findall(text):
        try:
            ipaddress.ip_network(m, strict=False)
            cidrs.add(m)
        except Exception:
            pass
    for m in IP_V4_RE.findall(text):
        if "/" not in m:
            try:
                ipaddress.ip_address(m)
                cidrs.add(m + "/32")
            except Exception:
                pass
    # handle simple ranges like 1.2.3.0 - 1.2.3.255
    for start, end in IP_RANGE_RE.findall(text):
        try:
            s = ipaddress.ip_address(start)
            e = ipaddress.ip_address(end)
            # convert to network(s) (summarize_address_range)
            nets = ipaddress.summarize_address_range(s, e)
            for n in nets:
                cidrs.add(str(n))
        except Exception:
            pass
    return sorted(cidrs)


# Parse common JSON shapes for IP ranges
def parse_common_range_json(obj) -> List[str]:
    out: Set[str] = set()
    if isinstance(obj, dict):
        # AWS style
        for key in ("prefixes", "ipv4_prefixes", "ipv6_prefixes", "addresses", "networks", "items", "edges"):
            val = obj.get(key)
            if not val:
                continue
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        if "/" in item:
                            out.add(item)
                    elif isinstance(item, dict):
                        # common dict shapes
                        for k in ("ip_prefix", "ipv6_prefix", "ipv4Prefix", "ipv6Prefix", "prefix", "network", "cidr"):
                            v = item.get(k)
                            if isinstance(v, str) and "/" in v:
                                out.add(v)
                        # sometimes addresses list contains plain IPs
                        for v in item.values():
                            if isinstance(v, str) and "/" in v:
                                out.add(v)
    elif isinstance(obj, list):
        for el in obj:
            if isinstance(el, str) and "/" in el:
                out.add(el)
            elif isinstance(el, dict):
                out.update(parse_common_range_json(el))
    return sorted(out)


# HTTP fetch wrapper
def http_get_text(session: requests.Session, url: str, timeout: Optional[int] = None) -> Optional[Tuple[str, int]]:
    try:
        to = timeout or getattr(session, "request_timeout", 8)
        r = session.get(url, timeout=to, allow_redirects=True, verify=True)
        return r.text, r.status_code
    except requests.exceptions.SSLError:
        # try once with verify=False
        try:
            r = session.get(url, timeout=timeout or 8, allow_redirects=True, verify=False)
            return r.text, getattr(r, "status_code", None)
        except Exception:
            return None
    except Exception:
        return None


# BGPView fallback for ASNs (best-effort)
def get_prefixes_from_asn(session: requests.Session, asn: int) -> List[str]:
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    out: List[str] = []
    try:
        res = http_get_text(session, url, timeout=6)
        if not res:
            return out
        text, status = res
        j = json.loads(text)
        data = j.get("data", {})
        for p in data.get("ipv4_prefixes", []) + data.get("ipv6_prefixes", []):
            prefix = p.get("prefix") or p.get("network")
            if prefix:
                out.append(prefix)
    except Exception:
        pass
    return out


# Fetch ranges for a provider (concurrent for provider's range_urls)
def fetch_ranges_for_provider(session: requests.Session, provider: Dict, workers: int = 6) -> List[str]:
    ranges: Set[str] = set()
    urls = provider.get("range_urls") or []

    def _fetch(url: str) -> None:
        try:
            res = http_get_text(session, url)
            if not res:
                return
            text, status = res
            # try JSON
            parsed = None
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = None
            if parsed is not None:
                cidrs = parse_common_range_json(parsed)
                for c in cidrs:
                    ranges.add(c)
            # always try textual extraction
            for c in extract_cidrs(text):
                ranges.add(c)
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(2, workers)) as ex:
        futures = [ex.submit(_fetch, u) for u in urls]
        # wait for completion
        concurrent.futures.wait(futures, timeout=60)

    # asn fallback
    for asn in provider.get("asns", []) or []:
        try:
            prefixes = get_prefixes_from_asn(session, int(asn))
            for p in prefixes:
                ranges.add(p)
        except Exception:
            pass

    return sorted(ranges)


# Fetch all ranges (parallel across providers)
def fetch_all_ranges(cdn_db: Dict, workers: int = 10, quiet: bool = False) -> Dict[str, List[str]]:
    info("Fetching ranges for providers in cdn_db (this may take a while)...", quiet)
    out: Dict[str, List[str]] = {}
    providers = cdn_db.get("providers", {})
    session = make_session()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(2, workers)) as ex:
        future_map = {}
        for key, prov in providers.items():
            info(f"Queueing fetch for {prov.get('name','?')}...", quiet)
            future = ex.submit(fetch_ranges_for_provider, session, prov, workers=4)
            future_map[future] = (key, prov)
        for fut in concurrent.futures.as_completed(future_map):
            key, prov = future_map[fut]
            try:
                rngs = fut.result(timeout=120)
                out[key] = rngs
                ok(f"{prov.get('name')} -> {len(rngs)} prefixes", quiet)
            except Exception as e:
                warn(f"Failed to fetch ranges for {key}: {e}", quiet)

    # cache to disk
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"meta": {"fetched_at": time.time()}, "ranges": out}, f, indent=2)
        ok(f"Cached ranges to {CACHE_FILE}", quiet)
    except Exception as e:
        warn(f"Failed to write cache: {e}", quiet)
    return out


# Load cached ranges if available and not expired
def load_cached_ranges(cache_ttl: int = DEFAULT_CACHE_TTL) -> Dict[str, List[str]]:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            j = json.load(f)
        fetched = j.get("meta", {}).get("fetched_at", 0)
        if time.time() - fetched > cache_ttl:
            return {}
        return j.get("ranges", {}) or {}
    except Exception:
        return {}


# Check if IP belongs to ranges
def ip_in_ranges(ip: str, ranges: Dict[str, List[str]]) -> Optional[str]:
    try:
        ipobj = ipaddress.ip_address(ip)
    except Exception:
        return None
    for prov, lst in ranges.items():
        for r in lst:
            try:
                if ipobj in ipaddress.ip_network(r, strict=False):
                    return prov
            except Exception:
                continue
    return None


def cidr_overlaps(cidr: str, ranges: Dict[str, List[str]]) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    try:
        user_net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return result
    for prov, lst in ranges.items():
        overlaps: List[str] = []
        for r in lst:
            try:
                net = ipaddress.ip_network(r, strict=False)
                if user_net.overlaps(net):
                    overlaps.append(r)
            except Exception:
                continue
        if overlaps:
            result[prov] = overlaps
    return result


# DNS helpers
def get_cname_chain(domain: str) -> List[str]:
    chain: List[str] = []
    try:
        seen: Set[str] = set()
        current = domain
        while True:
            try:
                ans = dns.resolver.resolve(current, "CNAME")
            except dns.resolver.NoAnswer:
                break
            except Exception:
                break
            found = False
            for r in ans:
                target = str(r.target).rstrip(".")
                if target and target not in seen:
                    chain.append(target)
                    seen.add(target)
                    current = target
                    found = True
                    break
            if not found:
                break
    except Exception:
        pass
    return chain


def resolve_ips(domain: str) -> List[str]:
    out: List[str] = []
    for rtype in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for a in answers:
                out.append(str(a))
        except Exception:
            continue
    if not out:
        try:
            ip = socket.gethostbyname(domain)
            out.append(ip)
        except Exception:
            pass
    # deduplicate
    return list(dict.fromkeys(out))


# SSL issuer parser
def get_ssl_issuer(domain: str, timeout: int = 4) -> Optional[str]:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(timeout)
            s.connect((domain, 443))
            cert = s.getpeercert()
            issuer = cert.get("issuer")
            if not issuer:
                return None
            # convert tuple structure to readable string (CN=..., O=...)
            parts = []
            for rdn in issuer:
                for attr in rdn:
                    if len(attr) >= 2:
                        k, v = attr[0], attr[1]
                        parts.append(f"{k}={v}")
            return ",".join(parts).lower()
    except Exception:
        return None


# Quick org lookup via ipinfo.io (best-effort)
def ip_org_lookup(session: requests.Session, ip: str) -> Optional[str]:
    try:
        url = f"https://ipinfo.io/{ip}/json"
        res = http_get_text(session, url, timeout=4)
        if not res:
            return None
        text, status = res
        js = json.loads(text)
        return js.get("org") or js.get("company") or js.get("hostname")
    except Exception:
        return None


# Main analyzer
def analyze_target(
    target: str,
    cdn_db: Dict,
    ranges_cache: Dict[str, List[str]],
    output_json: bool = False,
    quiet: bool = False,
):
    print(ASCII)
    providers = cdn_db.get("providers", {})

    # CIDR input
    if "/" in target and not re.search("[a-zA-Z]", target):
        info(f"CIDR input detected: {target}", quiet)
        overlaps = cidr_overlaps(target, ranges_cache)
        if output_json:
            print(json.dumps({"target": target, "overlaps": overlaps}, indent=2))
            return
        if not overlaps:
            ok(f"No known CDN ranges overlap with {target}", quiet)
            return
        ok(f"{target} overlaps with these CDN providers:", quiet)
        for p, l in overlaps.items():
            name = providers.get(p, {}).get("name", p)
            print(Fore.GREEN + f"  - {name}: {len(l)} overlapping ranges" + Style.RESET_ALL)
        return

    # IP
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except Exception:
        is_ip = False

    session = make_session()
    if is_ip:
        info(f"Checking IP: {target}", quiet)
        prov = ip_in_ranges(target, ranges_cache)
        if prov:
            name = providers.get(prov, {}).get("name", prov)
            if output_json:
                print(json.dumps({"ip": target, "provider": prov}, indent=2))
            else:
                ok(f"IP {target} belongs to CDN provider: {name}", quiet)
            return
        org = ip_org_lookup(session, target)
        if org:
            for key, p in providers.items():
                tokens = p.get("org_tokens", [])
                for t in tokens:
                    if t in (org or "").lower():
                        ok(f"IP {target} org indicates CDN: {p.get('name')} (org='{org}')", quiet)
                        return
        warn(f"IP {target} not found in cached CDN ranges and org lookup didn't match known CDNs", quiet)
        return

    # Domain
    domain = target
    info(f"Analyzing domain: {domain}", quiet)
    # CNAME chain
    chain = get_cname_chain(domain)
    if chain:
        info(f"CNAME chain -> { ' -> '.join(chain) }", quiet)
        for cname in chain:
            for key, p in providers.items():
                for token in p.get("cname_tokens", []):
                    if token in cname.lower():
                        ok(f"CNAME suggests CDN: {p.get('name')}", quiet)
                        return
    # HTTP headers
    try:
        session = make_session()
        schema = "https"
        url = f"{schema}://{domain}"
        r = session.get(url, timeout=6, allow_redirects=True)
        headers = dict((k.lower(), v) for k, v in r.headers.items())
        status = getattr(r, "status_code", None)
        info(f"Got HTTP headers (status={status})", quiet)
        for key, p in providers.items():
            for htoken in p.get("header_tokens", []):
                for h, v in headers.items():
                    if htoken in h or htoken in str(v).lower():
                        ok(f"Header suggests CDN: {p.get('name')} (header: {h})", quiet)
                        return
    except Exception:
        # try plain get_http with fallback in other helpers
        pass

    # Resolve and check
    ips = resolve_ips(domain)
    if ips:
        info(f"Resolved IPs: {', '.join(ips)}", quiet)
        for ip in ips:
            prov = ip_in_ranges(ip, ranges_cache)
            if prov:
                ok(f"Resolved IP {ip} is in CDN provider ranges: {providers.get(prov,{}).get('name',prov)}", quiet)
                return
        # ip org lookup
        for ip in ips:
            org = ip_org_lookup(session, ip)
            if org:
                for key, p in providers.items():
                    for token in p.get("org_tokens", []):
                        if token in (org or "").lower():
                            ok(f"Org for IP {ip} suggests CDN: {p.get('name')} (org='{org}')", quiet)
                            return

    # SSL issuer
    issuer = get_ssl_issuer(domain)
    if issuer:
        info(f"SSL issuer: {issuer}", quiet)
        for key, p in providers.items():
            for token in p.get("issuer_tokens", []):
                if token in (issuer or ""):
                    ok(f"SSL issuer suggests CDN: {p.get('name')}", quiet)
                    return

    warn(f"No conclusive evidence that {domain} is behind a known CDN using current checks", quiet)


def main():
    parser = argparse.ArgumentParser(description="Byakugan — CDN detection & CIDR checker (improved)")
    parser.add_argument("target", nargs="?", help="domain, IP, or CIDR to analyze")
    parser.add_argument("--db", help="path to cdn_db.json", default=DEFAULT_DB)
    parser.add_argument("--update", action="store_true", help="fetch latest CDN ranges and update cache")
    parser.add_argument("--no-cache", action="store_true", help="do not use cache (force fetch)")
    parser.add_argument("--list-cdns", action="store_true", dest="list_cdns", help="list all CDNs defined in cdn_db.json")
    parser.add_argument("--format", choices=["pretty", "json"], default="pretty", help="output format")
    parser.add_argument("--export-json", help="export JSON result to file")
    parser.add_argument("--workers", type=int, default=8, help="concurrent workers for fetching")
    parser.add_argument("--cache-ttl", type=int, default=DEFAULT_CACHE_TTL, help="cache TTL in seconds")
    parser.add_argument("--quiet", action="store_true", help="suppress informational output")
    args = parser.parse_args()

    try:
        cdn_db = load_cdn_db(args.db)
    except Exception as e:
        err(str(e), args.quiet)
        sys.exit(2)

    if args.list_cdns:
        print(ASCII)
        for k, p in cdn_db.get("providers", {}).items():
            print(Fore.GREEN + f"{p.get('name','?')}" + Style.RESET_ALL + f"  (id: {k})")
            if p.get("range_urls"):
                for u in p.get("range_urls"):
                    print(f"    - src: {u}")
            if p.get("asns"):
                print(f"    - asns: {p.get('asns')}")
        return

    ranges: Dict[str, List[str]] = {}
    try:
        if args.update or args.no_cache:
            ranges = fetch_all_ranges(cdn_db, workers=args.workers, quiet=args.quiet)
        else:
            ranges = load_cached_ranges(cache_ttl=args.cache_ttl)
            if not ranges:
                ranges = fetch_all_ranges(cdn_db, workers=args.workers, quiet=args.quiet)
    except KeyboardInterrupt:
        warn("Interrupted by user", args.quiet)
        sys.exit(1)

    if not args.target:
        parser.print_help()
        return

    out_json = (args.format == "json")
    analyze_target(args.target, cdn_db, ranges, output_json=out_json, quiet=args.quiet)


if __name__ == "__main__":
    main()
