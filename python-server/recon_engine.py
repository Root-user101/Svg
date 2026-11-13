"""Scope-gated, low-rate reconnaissance engine.

Target requests are pinned to resolved globally-routable IP addresses. Redirects
are never followed. Only same-host pages and JavaScript are fetched.
"""
import concurrent.futures
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from html.parser import HTMLParser

MAX_HOSTS = 80
MAX_PAGES = 10
MAX_JS = 12
MAX_BODY = 200_000
PORTS = [80, 443, 8080, 8443, 8000, 3000]
JOBS = {}
LOCK = threading.Lock()
WORKERS = concurrent.futures.ThreadPoolExecutor(max_workers=1)
USER_AGENT = "BugBountyHQ-Recon/2.0 (+authorized low-rate research)"

def utcnow():
    return datetime.now(timezone.utc).isoformat()

def clean_host(value):
    value = (value or "").strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if (not value or len(value) > 253 or "/" in value or ":" in value
            or "@" in value or not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value)):
        raise ValueError("Enter a valid public DNS hostname, not a URL or IP/port.")
    return value

def in_scope(host, entries):
    host = (host or "").lower().rstrip(".")
    for item in entries:
        base = (item.get("host") or "").lower().strip().rstrip(".")
        if not base:
            continue
        if item.get("type") == "Wildcard domain":
            # A wildcard covers subdomains, not the apex/root hostname.
            if host.endswith("." + base):
                return True
        elif host == base:
            return True
    return False

def valid_recon_root(domain, entries):
    # The apex may be used for passive CT/Wayback queries when only *.domain is in scope.
    # host_check() still refuses to probe the apex unless it is explicitly in scope.
    return in_scope(domain, entries) or any(
        item.get("type") == "Wildcard domain"
        and (item.get("host") or "").lower().rstrip(".") == domain
        for item in entries
    )

def resolve_addresses(host):
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        raw = sorted({item[4][0] for item in infos})
    except Exception:
        return [], "DNS lookup failed"
    if not raw:
        return [], "No A/AAAA records"
    parsed = []
    for value in raw:
        try:
            parsed.append(ipaddress.ip_address(value))
        except ValueError:
            return [], "Invalid DNS address"
    # Refuse mixed public/private answers rather than silently ignoring private ones.
    if any(not address.is_global for address in parsed):
        return [], "Blocked: DNS returned a non-public address"
    return [str(address) for address in parsed], "resolved"

def _pinned_request(host, ip, port, scheme, path, timeout=5, limit=MAX_BODY):
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/javascript,application/json,*/*",
               "Connection": "close", "Host": host}
    conn = None
    try:
        if scheme == "https":
            class PinnedHTTPS(http.client.HTTPSConnection):
                def connect(self):
                    raw = socket.create_connection((ip, port), self.timeout)
                    self.sock = self._context.wrap_socket(raw, server_hostname=host)
            conn = PinnedHTTPS(host, port, timeout=timeout, context=ssl.create_default_context())
        else:
            class PinnedHTTP(http.client.HTTPConnection):
                def connect(self):
                    self.sock = socket.create_connection((ip, port), self.timeout)
            conn = PinnedHTTP(host, port, timeout=timeout)
        conn.request("GET", path or "/", headers=headers)
        response = conn.getresponse()
        body = response.read(limit + 1)
        return {"status": response.status, "headers": dict(response.getheaders()),
                "body": body[:limit].decode("utf-8", "replace"),
                "truncated": len(body) > limit}
    except Exception as exc:
        return {"error": str(exc)[:160]}
    finally:
        if conn:
            conn.close()

def fetch_target(host, scheme="https", path="/", limit=MAX_BODY):
    if scheme not in ("http", "https"):
        return {"error": "Unsupported scheme"}
    ips, reason = resolve_addresses(host)
    if not ips:
        return {"error": reason}
    port = 443 if scheme == "https" else 80
    return _pinned_request(host, ips[0], port, scheme, path, limit=limit)

def fetch_public_service(url, timeout=10, limit=1_000_000):
    """Fetch only fixed public intelligence providers, never target-supplied URLs."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in {
        "crt.sh", "web.archive.org", "rdap.org", "ipapi.co"
    }:
        return {"error": "External URL not allow-listed"}
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(limit + 1)
            return {"status": response.status, "body": body[:limit].decode("utf-8", "replace")}
    except Exception as exc:
        return {"error": str(exc)[:160]}

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.scripts = [], []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])

def dns_intel(host):
    result = {"host": host}
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3
        for kind in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
            try:
                answers = resolver.resolve(host, kind)
                result[kind] = [str(item)[:240] for item in answers][:12]
            except Exception:
                result[kind] = []
    except Exception:
        result["note"] = "Install dnspython to enable MX/NS/TXT lookups."
    return result

def update(job_id, **fields):
    with LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(fields)
            JOBS[job_id]["updated_at"] = utcnow()

def log(job_id, message, level="info"):
    with LOCK:
        if job_id in JOBS:
            events = JOBS[job_id]["events"]
            events.append({"at": utcnow(), "message": message, "level": level})
            JOBS[job_id]["events"] = events[-150:]

def add_result(job_id, category, item):
    with LOCK:
        if job_id in JOBS:
            rows = JOBS[job_id]["results"].setdefault(category, [])
            if item not in rows:
                rows.append(item)

def cert_transparency(domain):
    url = "https://crt.sh/?q=%25." + urllib.parse.quote(domain) + "&output=json"
    response = fetch_public_service(url, timeout=12, limit=2_000_000)
    names = set()
    if response.get("status") == 200:
        try:
            for row in json.loads(response["body"]):
                for raw in row.get("name_value", "").splitlines():
                    name = raw.strip().lower().lstrip("*.")
                    if name == domain or name.endswith("." + domain):
                        names.add(name)
        except Exception:
            pass
    return sorted(names)

def historical_urls(domain, scope):
    query = urllib.parse.quote(domain)
    url = ("https://web.archive.org/cdx/search/cdx?url=%2A." + query +
           "%2F%2A&output=json&fl=original&collapse=urlkey&filter=statuscode%3A200&limit=300")
    response = fetch_public_service(url, timeout=12, limit=1_500_000)
    found = set()
    if response.get("status") == 200:
        try:
            rows = json.loads(response["body"])
            for row in rows[1:]:
                raw = row[0] if row else ""
                parsed = urllib.parse.urlparse(raw)
                if parsed.hostname and in_scope(parsed.hostname.lower(), scope):
                    found.add(raw[:1500])
        except Exception:
            pass
    return sorted(found)[:300]

def rdap_domain(domain):
    response = fetch_public_service("https://rdap.org/domain/" + urllib.parse.quote(domain), timeout=8, limit=300_000)
    if response.get("status") != 200:
        return {"domain": domain, "note": response.get("error", "RDAP unavailable")}
    try:
        data = json.loads(response["body"])
        return {"domain": domain, "handle": data.get("handle"),
                "ldhName": data.get("ldhName"), "status": data.get("status", [])[:8],
                "nameservers": [x.get("ldhName") for x in data.get("nameservers", [])[:12]]}
    except Exception:
        return {"domain": domain, "note": "RDAP response could not be parsed"}

def ip_network_intel(ip):
    response = fetch_public_service("https://ipapi.co/" + urllib.parse.quote(ip) + "/json/", timeout=7, limit=100_000)
    if response.get("status") != 200:
        return {"ip": ip, "note": response.get("error", "IP intelligence unavailable")}
    try:
        data = json.loads(response["body"])
        return {"ip": ip, "asn": data.get("asn"), "org": data.get("org"),
                "network": data.get("network"), "country": data.get("country_name")}
    except Exception:
        return {"ip": ip, "note": "IP intelligence response could not be parsed"}

def host_check(host, job_id, scope):
    if not in_scope(host, scope):
        return
    ips, reason = resolve_addresses(host)
    add_result(job_id, "hosts", {"host": host, "ips": ips, "dns": reason})
    add_result(job_id, "dns", dns_intel(host))
    for ip in ips[:2]:
        add_result(job_id, "network_intel", ip_network_intel(ip))
    if not ips:
        return
    response = fetch_target(host, "https", "/", MAX_BODY)
    scheme = "https"
    if "status" not in response:
        response = fetch_target(host, "http", "/", MAX_BODY)
        scheme = "http"
    if "status" not in response:
        add_result(job_id, "web", {"host": host, "error": response.get("error", "No HTTP response")})
        return
    headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
    technologies = []
    for key in ("server", "x-powered-by", "x-generator"):
        if headers.get(key):
            technologies.append(key + ": " + headers[key][:120])
    security_headers = {
        key: headers.get(key) for key in (
            "strict-transport-security", "content-security-policy",
            "x-content-type-options", "x-frame-options",
            "referrer-policy", "permissions-policy"
        )
    }
    add_result(job_id, "web", {"host": host, "url": scheme + "://" + host + "/",
                "status": response["status"], "server": headers.get("server", ""),
                "technologies": technologies, "security_headers": security_headers})
    if scheme == "https":
        try:
            with socket.create_connection((ips[0], 443), timeout=5) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    add_result(job_id, "tls", {"host": host, "version": tls.version(),
                        "not_after": cert.get("notAfter", ""),
                        "subject": str(cert.get("subject", ""))[:300]})
        except Exception as exc:
            add_result(job_id, "tls", {"host": host, "error": str(exc)[:150]})
    cors = headers.get("access-control-allow-origin")
    if cors:
        add_result(job_id, "cors", {"host": host, "allow_origin": cors,
            "allow_credentials": headers.get("access-control-allow-credentials", "false")})

    # Bounded same-host crawl. Redirects are not followed and each connection is IP-pinned.
    queue = ["/"]
    visited = set()
    while queue and len(visited) < MAX_PAGES:
        path = queue.pop(0)
        if path in visited or not path.startswith("/") or path.startswith("//"):
            continue
        visited.add(path)
        page = response if path == "/" else fetch_target(host, scheme, path, MAX_BODY)
        if "body" not in page:
            continue
        parser = Links()
        try:
            parser.feed(page["body"])
        except Exception:
            continue
        for raw in parser.links[:100]:
            absolute = urllib.parse.urljoin(scheme + "://" + host + path, raw)
            parsed = urllib.parse.urlparse(absolute)
            if parsed.scheme in ("http", "https") and parsed.hostname == host:
                endpoint = parsed.path + (("?" + parsed.query) if parsed.query else "")
                add_result(job_id, "endpoints", {"host": host, "url": scheme + "://" + host + endpoint,
                                                   "source": "same-host crawl"})
                if parsed.path and parsed.path not in visited and len(queue) < MAX_PAGES:
                    queue.append(parsed.path)
        for raw in parser.scripts[:MAX_JS]:
            absolute = urllib.parse.urljoin(scheme + "://" + host + path, raw)
            parsed = urllib.parse.urlparse(absolute)
            if parsed.scheme in ("http", "https") and parsed.hostname == host:
                js_path = parsed.path + (("?" + parsed.query) if parsed.query else "")
                add_result(job_id, "javascript", {"host": host, "url": scheme + "://" + host + js_path})
                js = fetch_target(host, scheme, js_path, 150_000)
                if "body" in js:
                    for match in re.findall(r"""(?:"|')((?:/|\.\./)[A-Za-z0-9_./?=&%-]{2,180})(?:"|')""", js["body"]):
                        candidate = urllib.parse.urljoin(scheme + "://" + host + "/", match)
                        item = urllib.parse.urlparse(candidate)
                        if item.hostname == host:
                            add_result(job_id, "endpoints", {"host": host,
                                "url": scheme + "://" + host + item.path + (("?" + item.query) if item.query else ""),
                                "source": "JavaScript reference"})

def run_job(job_id, domain, scope, active_ports):
    try:
        update(job_id, status="running", stage="Passive discovery", progress=3)
        log(job_id, "Querying Certificate Transparency.")
        names = cert_transparency(domain)
        names = sorted(set([domain] + [n for n in names if in_scope(n, scope)]))[:MAX_HOSTS]
        for name in names:
            add_result(job_id, "discovered", {"host": name, "source": "Certificate Transparency"})
        log(job_id, f"Found {len(names)} unique in-scope hostnames.")
        update(job_id, stage="Historical URL intelligence", progress=15)
        for url in historical_urls(domain, scope):
            add_result(job_id, "historical_urls", {"url": url, "source": "Wayback CDX"})
        add_result(job_id, "domain_intel", rdap_domain(domain))
        update(job_id, stage="DNS, HTTP, TLS and crawl", progress=25, discovered=len(names))
        for index, host in enumerate(names):
            host_check(host, job_id, scope)
            update(job_id, progress=25 + int(55 * (index + 1) / max(1, len(names))), checked=index + 1)
            time.sleep(0.5)
        if active_ports:
            update(job_id, stage="Limited web-port checks", progress=84)
            log(job_id, "Checking only common web ports on public resolved addresses.")
            for host in names[:25]:
                ips, _ = resolve_addresses(host)
                if not ips:
                    continue
                for port in PORTS:
                    try:
                        with socket.create_connection((ips[0], port), timeout=1.0):
                            add_result(job_id, "ports", {"host": host, "ip": ips[0], "port": port, "state": "open"})
                    except Exception:
                        pass
                    time.sleep(0.08)
        update(job_id, status="completed", stage="Finished", progress=100, completed_at=utcnow())
        log(job_id, "Recon completed. Review all results against the current program policy.")
    except Exception as exc:
        update(job_id, status="failed", stage="Error", error=str(exc)[:300], completed_at=utcnow())
        log(job_id, "Job failed: " + str(exc)[:200], "error")

def start_job(domain, scope, active_ports=False):
    domain = clean_host(domain)
    normalized = []
    for item in scope:
        if not isinstance(item, dict):
            continue
        host = clean_host(item.get("host", ""))
        kind = item.get("type", "Exact hostname")
        if kind not in ("Wildcard domain", "Exact hostname", "API", "Mobile app", "Other"):
            raise ValueError("Unsupported scope asset type.")
        normalized.append({"host": host, "type": kind})
    if not normalized or not valid_recon_root(domain, normalized):
        raise ValueError("Target domain must match an asset in your supplied authorized scope list.")
    job_id = uuid.uuid4().hex[:12]
    job = {"id": job_id, "domain": domain, "status": "queued", "stage": "Queued",
           "progress": 0, "created_at": utcnow(), "updated_at": utcnow(), "events": [],
           "results": {}, "discovered": 0, "checked": 0, "active_ports": bool(active_ports)}
    with LOCK:
        if any(j["status"] in ("queued", "running") for j in JOBS.values()):
            raise ValueError("One recon job is already running in this worker.")
        JOBS[job_id] = job
    WORKERS.submit(run_job, job_id, domain, normalized, bool(active_ports))
    return job_id

def get_job(job_id):
    with LOCK:
        job = JOBS.get(job_id)
        return json.loads(json.dumps(job)) if job else None

def list_jobs():
    with LOCK:
        return [{"id": j["id"], "domain": j["domain"], "status": j["status"],
                 "progress": j["progress"], "stage": j["stage"], "created_at": j["created_at"]}
                for j in sorted(JOBS.values(), key=lambda x: x["created_at"], reverse=True)[:30]]
