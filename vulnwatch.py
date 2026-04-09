#!/usr/bin/env python3
"""
VulnWatch — Real-Time Vulnerability Monitor
============================================
Fixes in this version:
  - CISA KEV: only NEW entries (skips old historical ones)
  - Slack rate limit: 1.2s delay between messages
  - ThreatFox 401: fixed with anonymous auth header
  - Ransomware.live: increased timeout to 30s
  - OSV: filters by modified date properly
  - MAX_ALERTS_PER_RUN: cap to avoid flooding

INSTALL (one time):
    pip install requests feedparser packaging python-gitlab slack-sdk lxml

RUN:
    python3 vulnwatch.py

SCHEDULE (cron every 5 min):
    */5 * * * * /usr/bin/python3 /path/to/vulnwatch.py >> /var/log/vulnwatch.log 2>&1
"""

import os, re, json, hashlib, logging, time, concurrent.futures
from datetime import datetime, timezone, timedelta
from pathlib import Path
from html.parser import HTMLParser
from packaging.version import Version, InvalidVersion

import requests
import feedparser
import gitlab
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG — fill these in
# ══════════════════════════════════════════════════════════════════════════════

GITLAB_TOKEN       = os.getenv("GITLAB_TOKEN",       "glpat-xxxx")
GITLAB_URL         = os.getenv("GITLAB_URL",         "https://gitlab.com")
GITLAB_GROUP_ID    = os.getenv("GITLAB_GROUP_ID",    "")
GITLAB_PROJECT_IDS = os.getenv("GITLAB_PROJECT_IDS", "")  # comma-separated IDs

SLACK_BOT_TOKEN         = os.getenv("SLACK_BOT_TOKEN",         "xoxb-xxxx")
SLACK_ALERTS_CHANNEL    = os.getenv("SLACK_ALERTS_CHANNEL",    "#security-alerts")
SLACK_CONFIRMED_CHANNEL = os.getenv("SLACK_CONFIRMED_CHANNEL", "#security-confirmed")

NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # free: nvd.nist.gov/developers/request-an-api-key

CHECK_HOURS_BACK    = int(os.getenv("CHECK_HOURS_BACK",    "1"))   # look back 1 hour each run
MIN_SEVERITY        = os.getenv("MIN_SEVERITY",            "HIGH") # LOW/MEDIUM/HIGH/CRITICAL
SLACK_DELAY_SECONDS = 1.2   # stay under Slack rate limit (1 msg/sec)
MAX_ALERTS_PER_RUN  = int(os.getenv("MAX_ALERTS_PER_RUN", "20"))  # cap alerts per run

STATE_FILE = Path("vulnwatch_state.json")

# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("vulnwatch")

# ══════════════════════════════════════════════════════════════════════════════
#  STATE — deduplication, never alert twice
# ══════════════════════════════════════════════════════════════════════════════

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"seen_vulns": [], "seen_findings": []}

def save_state(state: dict):
    state["seen_vulns"]    = state["seen_vulns"][-10000:]
    state["seen_findings"] = state["seen_findings"][-10000:]
    STATE_FILE.write_text(json.dumps(state, indent=2))

def make_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:20]

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

class _StripHTML(HTMLParser):
    def __init__(self): super().__init__(); self._out = []
    def handle_data(self, d): self._out.append(d)
    def result(self): return " ".join(self._out).strip()

def strip_html(s: str) -> str:
    p = _StripHTML(); p.feed(s or ""); return p.result()

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "NEWS": 0}

def severity_passes(sev: str) -> bool:
    return SEVERITY_ORDER.get(sev.upper(), 0) >= SEVERITY_ORDER.get(MIN_SEVERITY.upper(), 3)

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

def extract_cve(text: str):
    m = CVE_RE.search(text)
    return m.group(0).upper() if m else None

def parse_dt(raw: str):
    if not raw: return None
    raw = raw.strip()
    if re.match(r"^\d{4}-\d{2}-\d{2}$", raw):
        try:
            return datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            return None
    for fmt in ["%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"]:
        try:
            dt = datetime.strptime(raw[:26], fmt[:len(raw)])
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None

# ══════════════════════════════════════════════════════════════════════════════
#  CATEGORY CLASSIFIER
# ══════════════════════════════════════════════════════════════════════════════

CATEGORIES = [
    ("💀 Zero-Day",       ["0day","zero-day","zero day","actively exploited","in the wild","poc"]),
    ("🌐 Web / AppSec",   ["xss","csrf","sql injection","sqli","ssrf","rce","remote code",
                            "deserialization","path traversal","injection","oauth","jwt",
                            "auth bypass","idor","xxe","open redirect"]),
    ("🏗️ Infra",          ["linux","windows server","active directory","ldap","kerberos","rdp",
                            "ssh","privilege escalation","kernel","driver","firmware","docker",
                            "kubernetes","k8s","hypervisor","vmware","container escape"]),
    ("☁️ Cloud",          ["aws","azure","gcp","google cloud","s3 bucket","iam","serverless",
                            "cloud misconfiguration","eks","aks","gke","azure ad","okta","entra"]),
    ("🔓 Data Breach",    ["data breach","data leak","leaked","exposed database","pii",
                            "personal data","credentials leaked","database dump","exfiltration"]),
    ("🦠 Malware",        ["ransomware","malware","trojan","backdoor","rootkit","botnet",
                            "infostealer","cryptominer","c2","command and control","lockbit",
                            "alphv","cl0p","blackbasta"]),
    ("📦 Supply Chain",   ["supply chain","dependency","npm package","pypi","rubygems","maven",
                            "typosquat","dependency confusion","malicious package","sbom"]),
    ("🔐 Crypto / Auth",  ["tls","ssl","certificate","openssl","encryption","weak cipher",
                            "key exposure","mfa bypass","saml","password","credential"]),
    ("📱 Mobile",         ["android","ios","iphone","mobile","apk","webkit"]),
    ("🏭 ICS / SCADA",    ["scada","ics","ot security","industrial control","plc","modbus"]),
]

def classify(title: str, desc: str) -> str:
    text = (title + " " + desc).lower()
    for label, kws in CATEGORIES:
        if any(k in text for k in kws):
            return label
    return "🔎 General"

# ══════════════════════════════════════════════════════════════════════════════
#  VULN SOURCES
# ══════════════════════════════════════════════════════════════════════════════

def fetch_cisa_kev() -> list[dict]:
    """CISA KEV — only entries added in the last CHECK_HOURS_BACK hours."""
    vulns  = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=20
        )
        r.raise_for_status()
        for v in r.json().get("vulnerabilities", []):
            dt = parse_dt(v.get("dateAdded", ""))
            if not dt: continue       # skip entries with no date
            if dt < cutoff: continue  # skip old entries
            cve_id = v.get("cveID", "")
            desc   = (
                f"{v.get('shortDescription','')} | "
                f"Product: {v.get('product','N/A')} ({v.get('vendor','N/A')}) | "
                f"Action: {v.get('requiredAction','N/A')}"
            )[:400]
            vulns.append({
                "id": cve_id or make_id(v.get("vulnerabilityName", "")),
                "title": f"{cve_id} — {v.get('vulnerabilityName','')}",
                "description": desc, "severity": "CRITICAL", "cvss": None,
                "category": "💀 Zero-Day", "source": "CISA KEV", "source_emoji": "🇺🇸",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": v.get("dateAdded", ""),
                "affected_packages": [], "affected_versions": "", "ecosystems": [],
            })
        log.info(f"CISA KEV: {len(vulns)} new entries")
    except Exception as e:
        log.error(f"CISA KEV: {e}")
    return vulns


def fetch_nvd() -> list[dict]:
    vulns = []
    try:
        end   = datetime.now(timezone.utc)
        start = end - timedelta(hours=CHECK_HOURS_BACK)
        fmt   = "%Y-%m-%dT%H:%M:%S.000"
        url   = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}"
        )
        hdrs = {"User-Agent": "VulnWatch/1.0"}
        if NVD_API_KEY: hdrs["apiKey"] = NVD_API_KEY
        r = requests.get(url, headers=hdrs, timeout=25)
        r.raise_for_status()
        for item in r.json().get("vulnerabilities", []):
            cve    = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc   = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            sev    = "UNKNOWN"; cvss = None
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                mx = cve.get("metrics", {}).get(key, [])
                if mx:
                    cd = mx[0].get("cvssData", {})
                    cvss = cd.get("baseScore")
                    sev  = cd.get("baseSeverity", mx[0].get("baseSeverity", "UNKNOWN")).upper()
                    break
            pkgs, vers = [], []
            for node in cve.get("configurations", [{}]):
                for n in node.get("nodes", []):
                    for cpe in n.get("cpeMatch", []):
                        parts = cpe.get("criteria", "").split(":")
                        if len(parts) > 4: pkgs.append(parts[4])
                        if cpe.get("versionEndExcluding"): vers.append(f"<{cpe['versionEndExcluding']}")
                        if cpe.get("versionEndIncluding"): vers.append(f"<={cpe['versionEndIncluding']}")
            vulns.append({
                "id": cve_id, "title": cve_id, "description": desc[:400],
                "severity": sev, "cvss": cvss,
                "category": classify(cve_id, desc),
                "source": "NVD/NIST", "source_emoji": "🛡️",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": cve.get("published", ""),
                "affected_packages": pkgs, "affected_versions": ",".join(vers), "ecosystems": [],
            })
        log.info(f"NVD: {len(vulns)} CVEs")
    except Exception as e:
        log.error(f"NVD: {e}")
    return vulns


def fetch_osv() -> list[dict]:
    """OSV.dev — package-level vulns with exact version ranges."""
    vulns  = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
    for eco in ["npm", "PyPI", "Go", "Maven", "RubyGems", "crates.io", "Packagist"]:
        try:
            r = requests.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"ecosystem": eco}},
                timeout=20
            )
            if r.status_code != 200: continue
            for v in r.json().get("vulns", []):
                mod_dt = parse_dt(v.get("modified", "") or v.get("published", ""))
                if mod_dt and mod_dt < cutoff: continue
                vid   = v.get("id", "")
                title = v.get("summary", vid)[:200]
                desc  = v.get("details", "")[:400]
                sev   = "UNKNOWN"; cvss = None
                for s in v.get("severity", []):
                    if s.get("type") == "CVSS_V3":
                        try:
                            cvss = float(s["score"])
                            sev  = ("CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7
                                    else "MEDIUM" if cvss >= 4 else "LOW")
                        except Exception: pass
                pkgs, vers = [], []
                for aff in v.get("affected", []):
                    pkg = aff.get("package", {})
                    if pkg.get("name"): pkgs.append(pkg["name"])
                    for rng in aff.get("ranges", []):
                        for ev in rng.get("events", []):
                            if "introduced" in ev: vers.append(f">={ev['introduced']}")
                            if "fixed"      in ev: vers.append(f"<{ev['fixed']}")
                vulns.append({
                    "id": vid, "title": title, "description": desc,
                    "severity": sev, "cvss": cvss,
                    "category": classify(title, desc),
                    "source": "OSV.dev", "source_emoji": "📦",
                    "url": f"https://osv.dev/vulnerability/{vid}",
                    "published": v.get("published", ""),
                    "affected_packages": pkgs, "affected_versions": ",".join(vers),
                    "ecosystems": [eco.lower()],
                })
        except Exception as e:
            log.warning(f"OSV {eco}: {e}")
    log.info(f"OSV: {len(vulns)} vulns")
    return vulns


RSS_FEEDS = [
    ("Microsoft MSRC",    "🪟", "https://api.msrc.microsoft.com/update-guide/rss",           "HIGH"),
    ("Cisco",             "🔵", "https://tools.cisco.com/security/center/psirtrss20.xml",     "HIGH"),
    ("Red Hat",           "🎩", "https://access.redhat.com/security/vulnerabilities/rss",     "HIGH"),
    ("Ubuntu",            "🟠", "https://ubuntu.com/security/notices/rss.xml",                "MEDIUM"),
    ("Palo Alto Unit42",  "🔥", "https://unit42.paloaltonetworks.com/feed/",                  "HIGH"),
    ("Fortinet",          "🛡",  "https://www.fortiguard.com/rss/ir.xml",                     "HIGH"),
    ("GitHub Advisories", "🐙", "https://github.com/advisories.atom",                         "HIGH"),
    ("The Hacker News",   "📡", "https://feeds.feedburner.com/TheHackersNews",                "NEWS"),
    ("Bleeping Computer", "💻", "https://www.bleepingcomputer.com/feed/",                     "NEWS"),
    ("Packet Storm",      "⚡", "https://rss.packetstormsecurity.com/files/",                 "HIGH"),
    ("SANS ISC",          "🌩️", "https://isc.sans.edu/rssfeed_full.xml",                     "HIGH"),
    ("Dark Reading",      "🌑", "https://www.darkreading.com/rss.xml",                        "NEWS"),
    ("Krebs on Security", "🕵️", "https://krebsonsecurity.com/feed/",                         "NEWS"),
    ("Exploit-DB",        "💥", "https://www.exploit-db.com/rss.xml",                         "HIGH"),
    ("Full Disclosure",   "📢", "https://seclists.org/rss/fulldisclosure.rss",                "HIGH"),
    ("CyberSecurityNews", "📰", "https://cybersecuritynews.com/feed/",                        "NEWS"),
]

NEWS_KWS = [
    "cve","vulnerabilit","exploit","zero-day","0day","rce","patch","advisory",
    "breach","malware","ransomware","backdoor","injection","overflow","escalation",
    "bypass","disclosure","poc","critical","remote code","data leak","actively exploited",
]

def fetch_rss_feeds() -> list[dict]:
    vulns  = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)

    def _one(feed_tuple):
        source, emoji, url, default_sev = feed_tuple
        items = []
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                pub_dt = None
                if hasattr(entry, "published_parsed") and entry.published_parsed:
                    try:
                        pub_dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
                    except Exception: pass
                if pub_dt and pub_dt < cutoff: continue
                title   = strip_html(entry.get("title", "")).strip()
                summary = strip_html(entry.get("summary", ""))[:400]
                if not title: continue
                if default_sev == "NEWS":
                    if not any(k in (title + " " + summary).lower() for k in NEWS_KWS): continue
                sev = default_sev
                if default_sev == "NEWS":
                    tu = title.upper()
                    if any(w in tu for w in ["CRITICAL","ZERO-DAY","0-DAY","RCE","ACTIVELY EXPLOITED"]): sev = "CRITICAL"
                    elif any(w in tu for w in ["HIGH","EXPLOIT","RANSOMWARE","BREACH","BACKDOOR"]): sev = "HIGH"
                    else: sev = "MEDIUM"
                cve = extract_cve(title + " " + summary)
                vid = cve if cve else make_id(entry.get("link", title) + source)
                items.append({
                    "id": vid, "title": title, "description": summary,
                    "severity": sev, "cvss": None,
                    "category": classify(title, summary),
                    "source": source, "source_emoji": emoji,
                    "url": entry.get("link", url),
                    "published": pub_dt.isoformat() if pub_dt else "",
                    "affected_packages": [], "affected_versions": "", "ecosystems": [],
                })
        except Exception as e:
            log.warning(f"RSS {source}: {e}")
        return items

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        for result in pool.map(_one, RSS_FEEDS):
            vulns.extend(result)
    log.info(f"RSS feeds: {len(vulns)} items")
    return vulns


def fetch_ransomware_live() -> list[dict]:
    vulns  = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
    try:
        r = requests.get(
            "https://api.ransomware.live/recentvictims",
            timeout=30,  # increased timeout
            headers={"User-Agent": "VulnWatch/1.0", "Accept": "application/json"}
        )
        r.raise_for_status()
        for v in (r.json() if isinstance(r.json(), list) else []):
            pub_dt = None
            for f in ["discovered", "published", "date"]:
                raw = v.get(f, "")
                if raw:
                    try:
                        pub_dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                        if not pub_dt.tzinfo: pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                        break
                    except Exception: pass
            if pub_dt and pub_dt < cutoff: continue
            group  = v.get("group_name", v.get("group", "Unknown")).upper()
            victim = v.get("victim", v.get("company", "Unknown"))
            vulns.append({
                "id": make_id(f"{group}-{victim}-{v.get('discovered','')}"),
                "title": f"[Ransomware] {group} → {victim}",
                "description": (
                    f"Group *{group}* claimed attack on *{victim}*. "
                    f"Sector: {v.get('activity','N/A')} | Country: {v.get('country','N/A')}"
                ),
                "severity": "CRITICAL", "cvss": None, "category": "🦠 Malware",
                "source": "Ransomware.live", "source_emoji": "🦠",
                "url": "https://www.ransomware.live",
                "published": pub_dt.isoformat() if pub_dt else "",
                "affected_packages": [], "affected_versions": "", "ecosystems": [],
            })
        log.info(f"Ransomware.live: {len(vulns)} new victims")
    except Exception as e:
        log.error(f"Ransomware.live: {e}")
    return vulns


def fetch_threatfox() -> list[dict]:
    vulns  = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            timeout=20,
            headers={"User-Agent": "VulnWatch/1.0", "Auth-Key": "anonymous"}  # fixed
        )
        r.raise_for_status()
        seen = set()
        for ioc in r.json().get("data", []):
            pub_dt = parse_dt((ioc.get("first_seen", "") or "").replace(" ", "T"))
            if pub_dt and pub_dt < cutoff: continue
            malware = ioc.get("malware", "Unknown")
            key     = make_id(malware + str(pub_dt.date() if pub_dt else ""))
            if key in seen: continue
            seen.add(key)
            conf = int(ioc.get("confidence_level", 50) or 50)
            vulns.append({
                "id": key,
                "title": f"[Threat Intel] {malware} IOC — {ioc.get('ioc_type','N/A')}",
                "description": (
                    f"*{malware}* detected. Type: {ioc.get('ioc_type')} | "
                    f"Threat: {ioc.get('threat_type','N/A')} | Confidence: {conf}%"
                ),
                "severity": "HIGH" if conf >= 75 else "MEDIUM", "cvss": None,
                "category": "🦊 Threat Intel",
                "source": "ThreatFox", "source_emoji": "🦊",
                "url": f"https://threatfox.abuse.ch/browse.php?search=malware%3A{malware}",
                "published": pub_dt.isoformat() if pub_dt else "",
                "affected_packages": [], "affected_versions": "", "ecosystems": [],
            })
        log.info(f"ThreatFox: {len(vulns)} IOC families")
    except Exception as e:
        log.error(f"ThreatFox: {e}")
    return vulns


# ══════════════════════════════════════════════════════════════════════════════
#  MANIFEST PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def parse_manifest(filename: str, content: str) -> list[tuple]:
    """Returns list of (package_name, version, ecosystem)."""
    try:
        fn = filename.lower()
        if   fn == "package-lock.json": return _npm_lock(content)
        elif fn == "yarn.lock":         return _yarn_lock(content)
        elif fn == "requirements.txt":  return _requirements(content)
        elif fn == "pipfile.lock":      return _pipfile_lock(content)
        elif fn == "go.sum":            return _go_sum(content)
        elif fn == "pom.xml":           return _pom_xml(content)
        elif fn == "gemfile.lock":      return _gemfile_lock(content)
        elif fn == "cargo.lock":        return _cargo_lock(content)
        elif fn == "composer.json":     return _composer_json(content)
    except Exception as e:
        log.warning(f"Parse error {filename}: {e}")
    return []

def _npm_lock(c):
    d = json.loads(c); out = []
    for name, info in d.get("packages", {}).items():
        if not name: continue
        n = name.split("node_modules/")[-1].lstrip("/")
        v = info.get("version", "")
        if n and v: out.append((n, v, "npm"))
    if not out:
        for n, info in d.get("dependencies", {}).items():
            v = info.get("version", "")
            if n and v: out.append((n, v, "npm"))
    return out

def _yarn_lock(c):
    out = []; cur = None
    for line in c.splitlines():
        h = re.match(r'^"?([^@\s"]+)@', line)
        if h: cur = h.group(1)
        v = re.match(r'^\s+version\s+"?([^\s"]+)"?', line)
        if v and cur: out.append((cur, v.group(1), "npm")); cur = None
    return out

def _requirements(c):
    out = []
    for line in c.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"): continue
        m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*[=~><]+\s*([^\s,;]+)', line)
        if m: out.append((m.group(1).lower(), m.group(2), "pypi"))
    return out

def _pipfile_lock(c):
    d = json.loads(c); out = []
    for sec in ["default", "develop"]:
        for n, info in d.get(sec, {}).items():
            v = info.get("version", "").lstrip("=")
            if n and v: out.append((n.lower(), v, "pypi"))
    return out

def _go_sum(c):
    out = []; seen = set()
    for line in c.splitlines():
        p = line.split()
        if len(p) < 2: continue
        mod = p[0]; ver = p[1].split("/")[0].lstrip("v")
        if (mod, ver) not in seen:
            seen.add((mod, ver)); out.append((mod, ver, "go"))
    return out

def _pom_xml(c):
    out = []
    try:
        from lxml import etree
        root = etree.fromstring(c.encode())
        ns   = {"m": "http://maven.apache.org/POM/4.0.0"}
        for dep in root.findall(".//m:dependency", ns):
            gid = dep.findtext("m:groupId", namespaces=ns) or ""
            aid = dep.findtext("m:artifactId", namespaces=ns) or ""
            ver = dep.findtext("m:version", namespaces=ns) or ""
            if gid and aid and ver and not ver.startswith("$"):
                out.append((f"{gid}:{aid}", ver, "maven"))
    except Exception as e:
        log.warning(f"pom.xml: {e}")
    return out

def _gemfile_lock(c):
    out = []; in_specs = False
    for line in c.splitlines():
        if line.strip() in ("GEM", "PATH", "GIT"): in_specs = False
        if "specs:" in line: in_specs = True; continue
        if in_specs:
            m = re.match(r'^\s{4}([A-Za-z0-9_\-\.]+)\s+\(([^\)]+)\)', line)
            if m: out.append((m.group(1), m.group(2), "rubygems"))
            elif re.match(r'^\S', line): in_specs = False
    return out

def _cargo_lock(c):
    out = []; name = ver = None
    for line in c.splitlines():
        nm = re.match(r'^name\s*=\s*"(.+)"', line)
        vm = re.match(r'^version\s*=\s*"(.+)"', line)
        if nm: name = nm.group(1)
        if vm: ver  = vm.group(1)
        if line.strip() == "" and name and ver:
            out.append((name, ver, "cargo")); name = ver = None
    return out

def _composer_json(c):
    d = json.loads(c); out = []
    for sec in ["require", "require-dev"]:
        for n, v in d.get(sec, {}).items():
            if n == "php": continue
            vc = re.sub(r"[\^~>=<\s]", "", v).split("|")[0].split(",")[0]
            if n and vc: out.append((n, vc, "packagist"))
    return out

# ══════════════════════════════════════════════════════════════════════════════
#  VERSION MATCHER
# ══════════════════════════════════════════════════════════════════════════════

def is_affected(installed: str, version_range: str) -> bool:
    if not version_range or version_range.strip() in ("", "N/A"):
        return True
    try:
        iv = Version(installed.strip().lstrip("vV"))
    except InvalidVersion:
        return True
    for cond in [c.strip() for c in version_range.split(",") if c.strip()]:
        rng = re.match(r"^([^\s]+)\s*-\s*([^\s]+)$", cond)
        if rng:
            try:
                lo = Version(rng.group(1).lstrip("vV"))
                hi = Version(rng.group(2).lstrip("vV"))
                if not (lo <= iv <= hi): return False
            except InvalidVersion: continue
            continue
        op = re.match(r"^(>=|<=|!=|==|>|<)\s*(.+)$", cond)
        if op:
            o, rv_str = op.group(1), op.group(2).strip().lstrip("vV")
            try:
                rv = Version(rv_str)
                checks = {">=": iv>=rv, "<=": iv<=rv, ">": iv>rv,
                          "<": iv<rv, "==": iv==rv, "!=": iv!=rv}
                if not checks.get(o, True): return False
            except InvalidVersion: continue
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  GITLAB SCANNER
# ══════════════════════════════════════════════════════════════════════════════

MANIFEST_FILES = [
    "package-lock.json", "yarn.lock",
    "requirements.txt",  "Pipfile.lock",
    "go.sum",            "pom.xml",
    "Gemfile.lock",      "Cargo.lock",
    "composer.json",
]

def get_gitlab_projects(gl) -> list:
    if GITLAB_PROJECT_IDS:
        projects = []
        for pid in GITLAB_PROJECT_IDS.split(","):
            pid = pid.strip()
            if pid:
                try: projects.append(gl.projects.get(int(pid)))
                except Exception as e: log.warning(f"Project {pid}: {e}")
        return projects
    if GITLAB_GROUP_ID:
        try:
            grp  = gl.groups.get(GITLAB_GROUP_ID)
            pids = grp.projects.list(all=True, include_subgroups=True)
            return [gl.projects.get(p.id) for p in pids]
        except Exception as e:
            log.error(f"GitLab group: {e}"); return []
    return gl.projects.list(all=True, membership=True)

def fetch_manifest_from_gitlab(project, filename: str):
    for branch in [getattr(project, "default_branch", None) or "main", "master", "develop"]:
        try:
            f = project.files.get(file_path=filename, ref=branch)
            return f.decode().decode("utf-8", errors="replace")
        except Exception: continue
    return None

def scan_repos_against_vulns(vulns_with_packages: list[dict]) -> list[dict]:
    findings = []
    if not GITLAB_TOKEN or GITLAB_TOKEN in ("glpat-xxxx", ""):
        log.warning("GITLAB_TOKEN not configured — skipping repo scan")
        return findings
    try:
        gl = gitlab.Gitlab(GITLAB_URL, private_token=GITLAB_TOKEN)
        gl.auth()
        projects = get_gitlab_projects(gl)
        log.info(f"Scanning {len(projects)} GitLab project(s)...")
    except Exception as e:
        log.error(f"GitLab connection error: {e}"); return findings

    for project in projects:
        log.info(f"  → {project.name_with_namespace}")
        for manifest_name in MANIFEST_FILES:
            content = fetch_manifest_from_gitlab(project, manifest_name)
            if not content: continue
            packages = parse_manifest(manifest_name, content)
            if not packages: continue
            log.info(f"    {manifest_name}: {len(packages)} packages")
            for vuln in vulns_with_packages:
                if not vuln.get("affected_packages"): continue
                affected_list = [p.strip().lower() for p in vuln["affected_packages"]]
                for pkg_name, pkg_version, ecosystem in packages:
                    if pkg_name.lower() not in affected_list: continue
                    if not is_affected(pkg_version, vuln.get("affected_versions", "")): continue
                    fixed = "check advisory"
                    for part in (vuln.get("affected_versions", "") or "").split(","):
                        part = part.strip()
                        if part.startswith("<") and not part.startswith("<="):
                            fixed = part[1:].strip(); break
                    findings.append({
                        "vuln": vuln,
                        "project_id": project.id,
                        "project_name": project.name_with_namespace,
                        "project_url": project.web_url,
                        "manifest_file": manifest_name,
                        "package_name": pkg_name,
                        "installed_version": pkg_version,
                        "fixed_version": fixed,
                        "ecosystem": ecosystem,
                        "severity": vuln["severity"],
                    })
                    log.warning(f"    ⚠️  MATCH: {pkg_name}@{pkg_version} → {vuln['id']} ({vuln['severity']})")
    return findings

# ══════════════════════════════════════════════════════════════════════════════
#  SLACK ALERTS
# ══════════════════════════════════════════════════════════════════════════════

SEV_COLOR = {"CRITICAL":"#CC0000","HIGH":"#E05C00","MEDIUM":"#D4A000",
             "LOW":"#2E7D32","UNKNOWN":"#666666","NEWS":"#4527A0"}
SEV_EMOJI = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡",
             "LOW":"🟢","UNKNOWN":"⚪","NEWS":"📰"}

_slack_client = None
def _slack():
    global _slack_client
    if _slack_client is None:
        _slack_client = WebClient(token=SLACK_BOT_TOKEN)
    return _slack_client

def _post_slack(channel: str, blocks: list, color: str, fallback: str):
    try:
        _slack().chat_postMessage(
            channel=channel, text=fallback,
            attachments=[{"color": color, "blocks": blocks}]
        )
    except SlackApiError as e:
        log.error(f"Slack [{channel}]: {e.response['error']}")

def send_raw_alert(vuln: dict):
    sev   = vuln.get("severity", "UNKNOWN")
    color = SEV_COLOR.get(sev, "#666666")
    semoj = SEV_EMOJI.get(sev, "⚪")
    cvss  = f" | CVSS: `{vuln['cvss']}`" if vuln.get("cvss") else ""
    _post_slack(SLACK_ALERTS_CHANNEL, [
        {"type":"section","text":{"type":"mrkdwn","text":
            f"{vuln['source_emoji']} *[{vuln['source']}]*  {semoj} `{sev}`  {vuln['category']}\n"
            f"*<{vuln['url']}|{vuln['title']}>*"}},
        {"type":"divider"},
        {"type":"section","text":{"type":"mrkdwn",
            "text":(vuln.get("description") or "_No description_")[:400]}},
        {"type":"section","fields":[
            {"type":"mrkdwn","text":f"*CVE / ID*\n`{vuln['id']}`"},
            {"type":"mrkdwn","text":f"*Severity*\n{semoj} {sev}{cvss}"},
            {"type":"mrkdwn","text":f"*Category*\n{vuln['category']}"},
            {"type":"mrkdwn","text":f"*Source*\n{vuln['source']}"},
        ]},
        {"type":"context","elements":[{"type":"mrkdwn",
            "text":f"📅 Published: {vuln.get('published','N/A')}  |  "
                   f"⏱ Detected: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"}]},
    ], color, f"[{sev}] {vuln['title']} — {vuln['source']}")

def send_confirmed_alert(finding: dict):
    vuln  = finding["vuln"]
    sev   = finding["severity"]
    color = SEV_COLOR.get(sev, "#666666")
    semoj = SEV_EMOJI.get(sev, "⚪")
    _post_slack(SLACK_CONFIRMED_CHANNEL, [
        {"type":"section","text":{"type":"mrkdwn","text":
            f"🚨 *CONFIRMED IMPACT — Your org is affected!*\n"
            f"{semoj} `{sev}`  |  *<{vuln['url']}|{vuln['id']}>*  |  {vuln['category']}"}},
        {"type":"divider"},
        {"type":"section","fields":[
            {"type":"mrkdwn","text":f"*Repository*\n<{finding['project_url']}|{finding['project_name']}>"},
            {"type":"mrkdwn","text":f"*Manifest File*\n`{finding['manifest_file']}`"},
            {"type":"mrkdwn","text":f"*Package*\n`{finding['package_name']}`"},
            {"type":"mrkdwn","text":f"*Installed*\n`{finding['installed_version']}` ❌"},
            {"type":"mrkdwn","text":f"*Fix Version*\n`{finding['fixed_version']}` ✅"},
            {"type":"mrkdwn","text":f"*Ecosystem*\n{finding['ecosystem']}"},
        ]},
        {"type":"section","text":{"type":"mrkdwn",
            "text":(vuln.get("description") or "")[:300]}},
        {"type":"context","elements":[{"type":"mrkdwn",
            "text":f"🔗 <{vuln['url']}|Full advisory>  |  "
                   f"Detected: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"}]},
    ], color,
    f"🚨 CONFIRMED: {finding['package_name']}@{finding['installed_version']} "
    f"in {finding['project_name']} — {vuln['id']} ({sev})")

def create_gitlab_issue(finding: dict):
    try:
        gl      = gitlab.Gitlab(GITLAB_URL, private_token=GITLAB_TOKEN)
        project = gl.projects.get(finding["project_id"])
        vuln    = finding["vuln"]
        sev     = finding["severity"]
        issue   = project.issues.create({
            "title": f"[VulnWatch] {sev}: {vuln['id']} in {finding['package_name']}@{finding['installed_version']}",
            "description": f"""## 🚨 Vulnerability Detected by VulnWatch

| Field | Value |
|---|---|
| **CVE / ID** | [{vuln['id']}]({vuln['url']}) |
| **Severity** | {sev} |
| **Category** | {vuln['category']} |
| **Package** | `{finding['package_name']}` |
| **Installed Version** | `{finding['installed_version']}` ❌ |
| **Fix Version** | `{finding['fixed_version']}` ✅ |
| **Manifest File** | `{finding['manifest_file']}` |
| **Ecosystem** | {finding['ecosystem']} |

### Description
{vuln.get('description','See advisory link.')}

### How to Fix
Update `{finding['package_name']}` to `{finding['fixed_version']}` in `{finding['manifest_file']}`.

### References
- [Full Advisory]({vuln['url']})
- [NVD](https://nvd.nist.gov/vuln/detail/{vuln['id']})

---
*Auto-created by VulnWatch*""",
            "labels": ["security", f"severity::{sev.lower()}", "vulnerability"],
        })
        log.info(f"GitLab issue: {issue.web_url}")
    except Exception as e:
        log.error(f"GitLab issue: {e}")

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    log.info("=" * 60)
    log.info("VulnWatch starting scan...")
    log.info("=" * 60)

    state         = load_state()
    seen_vulns    = set(state["seen_vulns"])
    seen_findings = set(state["seen_findings"])

    # Step 1: Fetch all vuln sources
    log.info("Step 1/4 — Fetching vulnerability feeds...")
    all_vulns = []
    all_vulns += fetch_cisa_kev()        # 🇺🇸 new KEV entries only
    all_vulns += fetch_osv()             # 📦 package-level vulns
    all_vulns += fetch_rss_feeds()       # 📡 16 RSS feeds in parallel
    all_vulns += fetch_nvd()             # 🛡️ CVE database
    all_vulns += fetch_ransomware_live() # 🦠 ransomware victims
    all_vulns += fetch_threatfox()       # 🦊 threat actor IOCs
    log.info(f"Total fetched: {len(all_vulns)}")

    # Step 2: Send raw alerts → #security-alerts
    log.info("Step 2/4 — Sending raw alerts to #security-alerts...")
    new_vulns   = []
    alerts_sent = 0
    for vuln in all_vulns:
        vid = vuln["id"]
        if vid in seen_vulns: continue
        seen_vulns.add(vid)
        new_vulns.append(vuln)
        if severity_passes(vuln["severity"]):
            if alerts_sent >= MAX_ALERTS_PER_RUN:
                log.info(f"  Hit MAX_ALERTS_PER_RUN ({MAX_ALERTS_PER_RUN}) — rest queued next run")
                break
            send_raw_alert(vuln)
            alerts_sent += 1
            time.sleep(SLACK_DELAY_SECONDS)  # rate limit protection

    log.info(f"  {len(new_vulns)} new | {alerts_sent} sent to Slack")

    # Step 3: Scan GitLab repos
    log.info("Step 3/4 — Scanning GitLab repos for affected packages...")
    scannable = [v for v in all_vulns if v.get("affected_packages")]
    log.info(f"  {len(scannable)} vulns have package data to match")
    findings = scan_repos_against_vulns(scannable)
    log.info(f"  {len(findings)} confirmed findings in your repos")

    # Step 4: Send confirmed alerts → #security-confirmed
    log.info("Step 4/4 — Sending confirmed impact alerts...")
    confirmed_sent = 0
    for finding in findings:
        fid = make_id(
            finding["vuln"]["id"] + str(finding["project_id"]) +
            finding["package_name"] + finding["installed_version"]
        )
        if fid in seen_findings: continue
        seen_findings.add(fid)
        send_confirmed_alert(finding)
        time.sleep(SLACK_DELAY_SECONDS)
        create_gitlab_issue(finding)
        confirmed_sent += 1

    log.info(f"  {confirmed_sent} new confirmed findings alerted")

    # Save state
    state["seen_vulns"]    = list(seen_vulns)
    state["seen_findings"] = list(seen_findings)
    save_state(state)

    log.info("=" * 60)
    log.info(f"✅ Done — New vulns: {len(new_vulns)} | Confirmed: {confirmed_sent}")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
