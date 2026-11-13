"""Conservative, scope-gated reconnaissance helpers for Bug Bounty HQ."""
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from html.parser import HTMLParser

MAX_HOSTS = 80
MAX_PAGES = 15
MAX_JS = 20
MAX_BODY = 300_000
PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000, 22, 21, 25, 3306, 5432]
JOBS = {}
LOCK = threading.Lock()
WORKERS = concurrent.futures.ThreadPoolExecutor(max_workers=1)
USER_AGENT = "BugBountyHQ-Recon/1.0 (+authorized security research; low-rate)"

def utcnow():
    return datetime.now(timezone.utc).isoformat()

def clean_host(value):
    value = (value or "").strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if not value or len(value) > 253 or "/" in value or ":" in value or "@" in value:
        raise ValueError("Enter a valid hostname, not a URL or IP/port.")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        raise ValueError("A public DNS domain name is required.")
    return value

def in_scope(host, entries):
    host = host.lower().rstrip(".")
    for item in entries:
        base = item.get("host", "").lower().strip().rstrip(".")
        kind = item.get("type", "Wildcard domain")
        if not base:
            continue
        if kind == "Wildcard domain":
            if host == base or host.endswith("." + base):
                return True
        elif host == base:
            return True
    return False

def resolve_public(host):
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = sorted({x[4][0] for x in infos})
    except Exception:
        return []
    public = []
    for raw in ips:
        try:
            ip = ipaddress.ip_address(raw)
            if ip.is_global:
                public.append(raw)
        except ValueError:
            pass
    return public

def fetch(url, timeout=6, limit=MAX_BODY):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json,*/*"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as response:
            data = response.read(limit + 1)
            return {"status": response.status, "headers": dict(response.headers.items()),
                    "body": data[:limit].decode("utf-8", "replace"), "truncated": len(data) > limit,
                    "final_url": response.geturl()}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "headers": dict(e.headers.items()), "body": "", "truncated": False, "final_url": url}
    except Exception as e:
        return {"error": str(e)[:180]}

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.scripts = [], []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])

def update(job_id, **fields):
    with LOCK:
        JOBS[job_id].update(fields)
        JOBS[job_id]["updated_at"] = utcnow()

def log(job_id, message, level="info"):
    with LOCK:
        JOBS[job_id]["events"].append({"at": utcnow(), "message": message, "level": level})
        JOBS[job_id]["events"] = JOBS[job_id]["events"][-150:]

def add_result(job_id, category, item):
    with LOCK:
        key = category
        rows = JOBS[job_id]["results"].setdefault(key, [])
        if item not in rows:
            rows.append(item)

def cert_transparency(domain):
    url = "https://crt.sh/?q=%25." + urllib.parse.quote(domain) + "&output=json"
    result = fetch(url, timeout=12, limit=2_000_000)
    names = set()
    if result.get("status") == 200:
        try:
            for row in json.loads(result["body"]):
                for name in row.get("name_value", "").splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith("." + domain) or name == domain:
                        names.add(name)
        except Exception:
            pass
    return sorted(names)

def host_check(host, job_id, scope):
    if not in_scope(host, scope):
        return
    ips = resolve_public(host)
    add_result(job_id, "hosts", {"host": host, "ips": ips, "dns": "resolved" if ips else "no public A/AAAA result"})
    if not ips:
        return
    for scheme, port in (("https", 443), ("http", 80)):
        url = scheme + "://" + host + "/"
        res = fetch(url, timeout=6, limit=MAX_BODY)
        if "status" in res:
            headers = {k.lower(): v for k, v in res.get("headers", {}).items()}
            tech = []
            for h in ("server", "x-powered-by", "x-generator"):
                if headers.get(h):
                    tech.append(h + ": " + headers[h][:120])
            security = {h: headers.get(h) for h in (
                "strict-transport-security", "content-security-policy", "x-content-type-options",
                "x-frame-options", "referrer-policy", "permissions-policy")}
            add_result(job_id, "web", {"host": host, "url": url, "status": res["status"],
                        "server": headers.get("server", ""), "technologies": tech,
                        "security_headers": security})
            if scheme == "https":
                try:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((host, 443), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as tls:
                            cert = tls.getpeercert()
                            add_result(job_id, "tls", {"host": host, "version": tls.version(),
                                "not_after": cert.get("notAfter", ""), "subject": str(cert.get("subject", ""))[:300]})
                except Exception as e:
                    add_result(job_id, "tls", {"host": host, "error": str(e)[:150]})
            if scheme == "https":
                cors = fetch(url, timeout=5, limit=1000)  # no cross-origin payloads or credentials
                if "status" in cors:
                    h = {k.lower(): v for k, v in cors.get("headers", {}).items()}
                    if "access-control-allow-origin" in h:
                        add_result(job_id, "cors", {"host": host, "allow_origin": h.get("access-control-allow-origin"),
                            "allow_credentials": h.get("access-control-allow-credentials", "false")})
            break
    # Limited same-host crawl only. Redirects are not followed.
    start = fetch("https://" + host + "/", timeout=6, limit=MAX_BODY)
    if "body" not in start:
        start = fetch("http://" + host + "/", timeout=6, limit=MAX_BODY)
    if "body" in start:
        parser = Links()
        try:
            parser.feed(start["body"])
        except Exception:
            pass
        base = start.get("final_url", "https://" + host + "/")
        for raw in parser.links[:80]:
            absolute = urllib.parse.urljoin(base, raw)
            u = urllib.parse.urlparse(absolute)
            if u.scheme in ("http", "https") and u.hostname == host:
                add_result(job_id, "endpoints", {"host": host, "url": absolute, "source": "homepage link"})
        for raw in parser.scripts[:MAX_JS]:
            absolute = urllib.parse.urljoin(base, raw)
            u = urllib.parse.urlparse(absolute)
            if u.scheme in ("http", "https") and u.hostname == host:
                add_result(job_id, "javascript", {"host": host, "url": absolute})

def run_job(job_id, domain, scope, active_ports):
    try:
        update(job_id, status="running", stage="Passive discovery", progress=5)
        log(job_id, "Querying Certificate Transparency (crt.sh).")
        names = cert_transparency(domain)
        names = sorted(set([domain] + [n for n in names if in_scope(n, scope)]))[:MAX_HOSTS]
        for n in names:
            add_result(job_id, "discovered", {"host": n, "source": "Certificate Transparency"})
        log(job_id, f"Collected {len(names)} unique in-scope hostnames.")
        update(job_id, stage="DNS and web checks", progress=25, discovered=len(names))
        for i, host in enumerate(names):
            if not in_scope(host, scope):
                continue
            host_check(host, job_id, scope)
            update(job_id, progress=25 + int(55 * (i + 1) / max(1, len(names))), checked=i + 1)
            time.sleep(0.35)
        if active_ports:
            update(job_id, stage="Limited TCP port checks", progress=82)
            log(job_id, "Running a low-rate TCP connect check on a small common-port list.")
            for host in names[:25]:
                ips = resolve_public(host)
                if not ips:
                    continue
                for port in PORTS:
                    try:
                        with socket.create_connection((ips[0], port), timeout=1.2):
                            add_result(job_id, "ports", {"host": host, "ip": ips[0], "port": port, "state": "open"})
                    except Exception:
                        pass
                    time.sleep(0.05)
        update(job_id, status="completed", stage="Finished", progress=100, completed_at=utcnow())
        log(job_id, "Recon completed. Review every result against the live program policy.")
    except Exception as exc:
        update(job_id, status="failed", stage="Error", error=str(exc)[:300], completed_at=utcnow())
        log(job_id, "Job failed: " + str(exc)[:200], "error")

def start_job(domain, scope, active_ports=False):
    domain = clean_host(domain)
    normalized = []
    for item in scope:
        try:
            h = clean_host(item.get("host", ""))
            normalized.append({"host": h, "type": item.get("type", "Wildcard domain")})
        except ValueError:
            continue
    if not normalized or not in_scope(domain, normalized):
        raise ValueError("Target domain must match an asset in your supplied authorized scope list.")
    job_id = uuid.uuid4().hex[:12]
    job = {"id": job_id, "domain": domain, "status": "queued", "stage": "Queued",
           "progress": 0, "created_at": utcnow(), "updated_at": utcnow(), "events": [],
           "results": {}, "discovered": 0, "checked": 0, "active_ports": bool(active_ports)}
    with LOCK:
        if sum(1 for j in JOBS.values() if j["status"] in ("queued", "running")) >= 1:
            raise ValueError("One recon job is already running. Wait for it to finish.")
        JOBS[job_id] = job
    WORKERS.submit(run_job, job_id, domain, normalized, bool(active_ports))
    return job_id

def get_job(job_id):
    with LOCK:
        job = JOBS.get(job_id)
        return json.loads(json.dumps(job)) if job else None

def list_jobs():
    with LOCK:
        return [ {"id": j["id"], "domain": j["domain"], "status": j["status"],
                  "progress": j["progress"], "stage": j["stage"], "created_at": j["created_at"]}
                 for j in sorted(JOBS.values(), key=lambda x: x["created_at"], reverse=True)[:30] ]
