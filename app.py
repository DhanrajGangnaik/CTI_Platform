import threading
import time
import json
import os
import hashlib
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone
from typing import Dict, List, Optional

import feedparser
import requests
from fastapi import FastAPI, Query, Form, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    Response,
    RedirectResponse,
)

# ------------------------------- Config --------------------------------

CATEGORIES: List[str] = [
    "Ransomware",
    "Vulnerabilities",
    "Data Breaches",
    "APT",
    "Phishing",
    "Cloud/SaaS",
    "Malware/Tools",
]

FEEDS: Dict[str, List[str]] = {
    "Ransomware": [
        "https://www.bleepingcomputer.com/tag/ransomware/feed/",
    ],
    "Vulnerabilities": [
        "https://thehackernews.com/feeds/posts/default/-/Vulnerability",
        "https://packetstormsecurity.com/files/tags/vulnerabilities/feed",
    ],
    "Data Breaches": [
        "https://www.bleepingcomputer.com/tag/data-breach/feed/",
    ],
    "APT": [
        "https://thehackernews.com/feeds/posts/default/-/APT",
        "https://www.bleepingcomputer.com/tag/advanced-persistent-threats/feed/",
    ],
    "Phishing": [
        "https://www.bleepingcomputer.com/tag/phishing/feed/",
        "https://thehackernews.com/feeds/posts/default/-/Phishing",
    ],
    "Cloud/SaaS": [
        "https://cloud.google.com/blog/topics/security/rss/",
    ],
    "Malware/Tools": [
        "https://www.bleepingcomputer.com/tag/malware/feed/",
    ],
}

IOC_SOURCE = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

# AlienVault OTX (optional; used if API key is set as env var)
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()

# Per-category search phrases for OTX
API_QUERIES: Dict[str, Dict[str, str]] = {
    "Ransomware":      {"otx": "ransomware"},
    "Vulnerabilities": {"otx": "cve OR vulnerability"},
    "Data Breaches":   {"otx": "data breach leaked records"},
    "APT":             {"otx": "APT group OR nation-state"},
    "Phishing":        {"otx": "phishing campaign credential stealing"},
    "Cloud/SaaS":      {"otx": "cloud security breach OR saas compromise"},
    "Malware/Tools":   {"otx": "malware loader OR infostealer"},
}

CACHE_TTL_SECONDS = 10 * 60
BACKGROUND_REFRESH_SECONDS = 10 * 60

USERS_FILE = "users.json"

# SMTP (optional – required for real email sending)
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or "587")
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "")

SESSION_COOKIE_NAME = "ci_email"

# ------------------------------ App/Core -------------------------------

app = FastAPI(title="CyberIntel – Tiles View")
app.add_middleware(GZipMiddleware, minimum_size=512)

_cache_lock = threading.Lock()
_news_cache: Dict[str, Dict] = {}
_last_build_time_iso = datetime.now(timezone.utc).isoformat()
_seen_ids = set()  # title+link we’ve already notified about


def _now() -> float:
    return time.time()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_entry(entry) -> Dict:
    title = (entry.get("title") or "").strip()
    link = entry.get("link") or ""
    summary = (entry.get("summary") or entry.get("description") or "").strip()
    source = (entry.get("source", {}) or {}).get("title") or entry.get("author") or ""
    published_parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if published_parsed:
        published = datetime(*published_parsed[:6], tzinfo=timezone.utc).isoformat()
    else:
        published = _iso_now()
    return {
        "title": title,
        "link": link,
        "summary": summary,
        "source": source,
        "published": published,
    }


# -------------------- User storage + email helpers ---------------------

def _load_users() -> List[Dict]:
    if not os.path.exists(USERS_FILE):
        return []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_users(users: List[Dict]) -> None:
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def _get_user_by_email(email: str) -> Optional[Dict]:
    for u in _load_users():
        if u.get("email") == email:
            return u
    return None


def _register_or_update_user(username: str, email: str, password: str) -> (Dict, bool):
    """
    Create or update a user.
    Returns (user_dict, is_new_user).
    """
    users = _load_users()
    pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    email = email.strip()
    username = username.strip()

    existing = None
    for u in users:
        if u.get("email") == email:
            existing = u
            break

    if existing:
        existing["username"] = username
        existing["password_hash"] = pwd_hash
        is_new = False
    else:
        existing = {
            "username": username,
            "email": email,
            "password_hash": pwd_hash,
            "created": _iso_now(),
        }
        users.append(existing)
        is_new = True

    _save_users(users)
    return existing, is_new


def _send_email(to_addr: str, subject: str, body: str) -> None:
    """Send email if SMTP is configured; otherwise do nothing."""
    if not (SMTP_HOST and SMTP_FROM and to_addr):
        return
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception:
        # best effort only
        pass


def _send_welcome_email(user: Dict) -> None:
    if not user.get("email"):
        return
    subject = "Welcome to the CyberIntel community"
    body = (
        f"Hey {user.get('username') or 'there'},\n\n"
        "You’re now part of the CyberIntel community. "
        "We’ll keep pulling interesting security stories into your dashboard.\n\n"
        "You can come back any time to explore new headlines or update your account.\n\n"
        "Stay safe,\nCyberIntel"
    )
    _send_email(user["email"], subject, body)


def _notify_new_items(new_items: List[Dict]) -> None:
    """Send a simple notification email when new content appears."""
    if not new_items:
        return
    users = _load_users()
    if not users:
        return

    lines = []
    for it in new_items[:5]:
        lines.append(f"- {it.get('title','(untitled)')} :: {it.get('link','#')}")
    body = "New security stories were just added to CyberIntel:\n\n" + "\n".join(lines)

    for u in users:
        email = u.get("email")
        if email:
            _send_email(email, "CyberIntel – New security stories", body)


def _current_user(request: Request) -> Optional[Dict]:
    email = request.cookies.get(SESSION_COOKIE_NAME)
    if not email:
        return None
    return _get_user_by_email(email)


# ----------------------- External intel helpers ------------------------

def _fetch_feodo_iocs(max_items: int = 25) -> List[Dict]:
    """Feodo Tracker IPs as IOC cards with varied summaries."""
    if not IOC_SOURCE:
        return []

    try:
        resp = requests.get(IOC_SOURCE, timeout=10)
        resp.raise_for_status()
        lines = [
            ln.strip()
            for ln in resp.text.splitlines()
            if ln and not ln.startswith("#")
        ]
    except Exception:
        return []

    templates = [
        "Feodo Tracker lists {ip} as an active command-and-control endpoint used by banking malware.",
        "Suspicious host {ip} is currently flagged in the Feodo Tracker blocklist for C2 activity.",
        "Abuse.ch FeodoTracker reports {ip} as part of a botnet infrastructure serving malicious traffic.",
        "Indicator {ip} is tagged by Feodo Tracker as a high-risk C2 node associated with credential theft.",
    ]

    items: List[Dict] = []
    for idx, ip in enumerate(lines[:max_items]):
        summary = templates[idx % len(templates)].format(ip=ip)
        items.append(
            {
                "title": f"Feodo C2 IP {ip}",
                "link": "https://feodotracker.abuse.ch/browse/",
                "summary": summary,
                "source": "Abuse.ch Feodo Tracker",
                "published": _iso_now(),
            }
        )
    return items


def _fetch_otx_for_category(cat: str, max_items: int = 25) -> List[Dict]:
    """AlienVault OTX pulses per category."""
    if not OTX_API_KEY:
        return []

    qinfo = API_QUERIES.get(cat) or {}
    query = qinfo.get("otx")
    if not query:
        return []

    try:
        url = "https://otx.alienvault.com/api/v1/search/pulses"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        params = {"q": query, "page": 1}
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
    except Exception:
        return []

    items: List[Dict] = []
    for p in data.get("results", [])[:max_items]:
        pulse_id = p.get("id") or ""
        link = (
            f"https://otx.alienvault.com/pulse/{pulse_id}"
            if pulse_id
            else "https://otx.alienvault.com/"
        )

        items.append(
            {
                "title": (p.get("name") or "OTX pulse").strip(),
                "link": link,
                "summary": (p.get("description") or "").strip(),
                "source": "AlienVault OTX",
                "published": p.get("modified")
                or p.get("created")
                or _iso_now(),
            }
        )
    return items


# -------------------------- Fallback content ---------------------------

def _fallback_items(cat: str) -> List[Dict]:
    now = _iso_now()
    base = {
        "Ransomware": [
            {
                "title": "CISA Ransomware Guidance & Resources",
                "link": "https://www.cisa.gov/stopransomware",
                "summary": "Official CISA hub with advisories, checklists, and prevention guidance for ransomware.",
                "source": "CISA",
                "published": now,
            },
            {
                "title": "Nomoreransom.org Decryption Tools",
                "link": "https://www.nomoreransom.org/en/decryption-tools.html",
                "summary": "Repository of free decryption tools and advice for victims of common ransomware families.",
                "source": "No More Ransom",
                "published": now,
            },
        ],
        "Vulnerabilities": [
            {
                "title": "NVD – National Vulnerability Database",
                "link": "https://nvd.nist.gov/vuln/search",
                "summary": "Search and browse CVEs with CVSS scoring, references, and impact information.",
                "source": "NIST",
                "published": now,
            },
            {
                "title": "CISA Known Exploited Vulnerabilities Catalog",
                "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "summary": "Authoritative list of CVEs that are known to be actively exploited in the wild.",
                "source": "CISA",
                "published": now,
            },
        ],
        "Data Breaches": [
            {
                "title": "Have I Been Pwned – Latest Breaches",
                "link": "https://haveibeenpwned.com/PwnedWebsites",
                "summary": "Directory of public data breaches with summary, dates and types of exposed data.",
                "source": "Have I Been Pwned",
                "published": now,
            },
            {
                "title": "Privacy Rights Clearinghouse Data Breach Chronology",
                "link": "https://privacyrights.org/data-breaches",
                "summary": "Historical log of reported data breaches with filters for industry and cause.",
                "source": "Privacy Rights Clearinghouse",
                "published": now,
            },
        ],
        "APT": [
            {
                "title": "MITRE ATT&CK – Groups",
                "link": "https://attack.mitre.org/groups/",
                "summary": "Catalog of tracked threat groups (APTs) with techniques, software and campaigns.",
                "source": "MITRE",
                "published": now,
            },
            {
                "title": "Mandiant – Threat Intelligence Blog",
                "link": "https://www.mandiant.com/resources/blog",
                "summary": "Research articles on nation-state and financially motivated intrusion campaigns.",
                "source": "Mandiant",
                "published": now,
            },
        ],
        "Phishing": [
            {
                "title": "APWG Phishing Activity Trends Report",
                "link": "https://apwg.org/trendsreports/",
                "summary": "Regular reports with metrics on phishing volumes, lures, and targeted brands.",
                "source": "APWG",
                "published": now,
            },
            {
                "title": "Google – How to Recognize & Avoid Phishing",
                "link": "https://safety.google/security/phishing-prevention/",
                "summary": "Practical guidance for spotting and reporting phishing attempts.",
                "source": "Google Safety",
                "published": now,
            },
        ],
        "Cloud/SaaS": [
            {
                "title": "AWS Security Blog – Cloud Best Practices",
                "link": "https://aws.amazon.com/blogs/security/",
                "summary": "Updates and deep dives on securing workloads on AWS and hybrid environments.",
                "source": "AWS",
                "published": now,
            },
            {
                "title": "Google Cloud Security Blog",
                "link": "https://cloud.google.com/blog/topics/security",
                "summary": "Product updates, incident write-ups and best practices for Google Cloud.",
                "source": "Google Cloud",
                "published": now,
            },
            {
                "title": "Microsoft Security Blog – Cloud & Identity",
                "link": "https://www.microsoft.com/security/blog/",
                "summary": "Posts on SaaS security, identity protection and threat intelligence.",
                "source": "Microsoft",
                "published": now,
            },
        ],
        "Malware/Tools": [
            {
                "title": "Malwarebytes Labs – Threat Intelligence",
                "link": "https://www.malwarebytes.com/blog/threat-intelligence",
                "summary": "Research articles on new malware families, loaders, and crimeware trends.",
                "source": "Malwarebytes",
                "published": now,
            },
            {
                "title": "BleepingComputer – Malware News",
                "link": "https://www.bleepingcomputer.com/malware/",
                "summary": "News and analysis on active malware campaigns and defensive tools.",
                "source": "BleepingComputer",
                "published": now,
            },
            {
                "title": "KrebsOnSecurity – Tools & Attacks",
                "link": "https://krebsonsecurity.com/",
                "summary": "In-depth investigations into cybercrime operations and malware ecosystems.",
                "source": "KrebsOnSecurity",
                "published": now,
            },
        ],
    }
    return base.get(cat, [])


# ------------------------- Category aggregation ------------------------

def _fetch_category(cat: str) -> List[Dict]:
    items: List[Dict] = []

    # RSS
    for url in FEEDS.get(cat, []):
        try:
            feed = feedparser.parse(url)
            for e in feed.get("entries", [])[:30]:
                items.append(_normalize_entry(e))
        except Exception:
            continue

    # OTX
    try:
        items.extend(_fetch_otx_for_category(cat))
    except Exception:
        pass

    # Feodo IOC cards
    if cat in ("Ransomware", "Malware/Tools", "APT"):
        try:
            items.extend(_fetch_feodo_iocs())
        except Exception:
            pass

    # De-dupe & sort
    seen = set()
    uniq: List[Dict] = []
    for it in items:
        key = (it.get("title"), it.get("link"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(it)

    uniq.sort(key=lambda x: x["published"], reverse=True)
    return uniq[:60]


def _ensure_fresh(cat: str) -> Dict:
    """
    Returns a cached bucket for a category. If feeds return nothing,
    we fall back to curated links instead of empty tiles.
    Also triggers email notifications for brand-new items.
    """
    global _last_build_time_iso, _seen_ids
    with _cache_lock:
        bucket = _news_cache.get(cat)
        if not bucket or (_now() - bucket["ts"] > CACHE_TTL_SECONDS):
            items = _fetch_category(cat)
            if not items:
                items = _fallback_items(cat)
            if not items:
                items = [{
                    "title": f"{cat} – no live headlines right now",
                    "link": "#",
                    "summary": "Nothing live from the feeds at this moment.",
                    "source": "System",
                    "published": _iso_now(),
                }]

            # detect new items for notifications
            new_items: List[Dict] = []
            for it in items:
                key = (it.get("title"), it.get("link"))
                if key not in _seen_ids and it.get("link") not in ("", "#"):
                    _seen_ids.add(key)
                    new_items.append(it)

            if new_items:
                _notify_new_items(new_items)

            bucket = {"ts": _now(), "items": items}
            _news_cache[cat] = bucket
            _last_build_time_iso = _iso_now()
        return bucket


def _prewarm():
    for c in CATEGORIES:
        try:
            _ensure_fresh(c)
        except Exception:
            pass


def _background_refresher():
    while True:
        try:
            _prewarm()
        except Exception:
            pass
        time.sleep(BACKGROUND_REFRESH_SECONDS)


threading.Thread(target=_background_refresher, daemon=True).start()

# ------------------------------- API -----------------------------------

@app.get("/api/news", response_class=JSONResponse)
def api_news(limit: int = Query(60, ge=1, le=200)):
    """
    Frontend just shows an 'All stories' tile wall, so we aggregate
    all categories into one list.
    """
    merged: List[Dict] = []
    for c in CATEGORIES:
        merged.extend(_ensure_fresh(c)["items"])
    merged.sort(key=lambda x: x["published"], reverse=True)
    merged = merged[:limit]
    return {"items": merged, "total_all": len(merged), "updated": _last_build_time_iso}


@app.post("/api/refresh", response_class=JSONResponse)
def api_refresh():
    with _cache_lock:
        _news_cache.clear()
    _prewarm()
    return {"status": "ok", "updated": _last_build_time_iso}


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)


# ------------------------------- HTML ----------------------------------

INDEX_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>CyberIntel – Live Threat Tiles</title>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root{
      --bg-top:#2A3056;
      --bg-bottom:#294933;
      --card:#2A3056;
      --accent:#67FFF2;
      --accent-alt:#81EC86;
      --ink:#F6F7FF;
      --ink-muted:#9FB3D2;
      --border-subtle:rgba(255,255,255,0.06);
    }
    *{box-sizing:border-box;margin:0;padding:0}
    body{
      color:var(--ink);
      font:14px/1.5 "Poppins",system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Ubuntu,"Helvetica Neue",Arial,sans-serif;
      background:
        radial-gradient(circle at 0% 0%, rgba(103,255,242,0.22) 0, transparent 55%),
        radial-gradient(circle at 100% 100%, rgba(129,236,134,0.18) 0, transparent 55%),
        linear-gradient(135deg,var(--bg-top),var(--bg-bottom));
      min-height:100vh;
      padding:28px 42px 40px;
    }
    a{color:inherit;text-decoration:none}
    a:hover{text-decoration:underline}

    .shell{
      max-width:1280px;
      margin:0 auto;
    }

    /* Header bar */
    .topbar{
      display:flex;
      align-items:center;
      justify-content:space-between;
      margin-bottom:26px;
      gap:16px;
    }
    .brand{
      display:flex;
      flex-direction:column;
      gap:3px;
    }
    .brand-title{
      font-size:26px;
      font-weight:700;
      letter-spacing:.05em;
    }
    .brand-sub{
      font-size:12px;
      color:var(--ink-muted);
    }

    .auth-btn{
      padding:8px 16px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,0.16);
      background:linear-gradient(135deg,var(--accent),var(--accent-alt));
      color:#021118;
      font-size:13px;
      font-weight:600;
      letter-spacing:.05em;
      text-transform:uppercase;
      display:inline-flex;
      align-items:center;
      gap:6px;
      cursor:pointer;
      box-shadow:0 14px 32px rgba(0,0,0,0.45);
      transition:transform .16s ease, box-shadow .16s ease, filter .16s ease;
    }
    .auth-btn span.icon{
      font-size:16px;
      transform:translateY(-1px);
    }
    .auth-btn:hover{
      transform:translateY(-2px);
      box-shadow:0 18px 40px rgba(0,0,0,0.6);
      filter:brightness(1.05);
      text-decoration:none;
    }
    .auth-btn:active{
      transform:translateY(0);
      box-shadow:0 10px 24px rgba(0,0,0,0.45);
    }

    .user-chip{
      display:flex;
      align-items:center;
      gap:10px;
      background:rgba(0,0,0,0.45);
      border-radius:999px;
      padding:6px 10px 6px 6px;
      border:1px solid rgba(255,255,255,0.16);
      box-shadow:0 14px 32px rgba(0,0,0,0.5);
    }
    .user-avatar{
      width:28px;
      height:28px;
      border-radius:999px;
      background:linear-gradient(135deg,var(--accent),var(--accent-alt));
      display:flex;
      align-items:center;
      justify-content:center;
      font-weight:600;
      color:#021118;
      font-size:14px;
    }
    .user-meta{
      display:flex;
      flex-direction:column;
      gap:2px;
    }
    .user-name{
      font-size:13px;
      font-weight:500;
    }
    .user-email{
      font-size:11px;
      color:var(--ink-muted);
    }
    .user-actions{
      display:flex;
      flex-direction:column;
      gap:4px;
      margin-left:6px;
      border-left:1px solid rgba(255,255,255,0.12);
      padding-left:8px;
    }
    .user-actions a{
      font-size:11px;
      color:var(--accent);
      text-decoration:none;
    }
    .user-actions a:hover{
      text-decoration:underline;
    }

    .meta-row{
      margin-bottom:18px;
      display:flex;
      justify-content:space-between;
      gap:10px;
      font-size:12px;
      color:var(--ink-muted);
      flex-wrap:wrap;
    }

    /* Tile grid */
    .grid{
      display:grid;
      grid-template-columns:repeat(auto-fit,minmax(260px,1fr));
      gap:16px;
    }

    @keyframes floatIn {
      0%{opacity:0; transform:translateY(8px) scale(0.98);}
      100%{opacity:1; transform:translateY(0) scale(1);}
    }

    .card{
      background:rgba(0,0,0,0.38);
      border-radius:18px;
      padding:13px 14px 12px;
      border:1px solid rgba(255,255,255,0.04);
      display:flex;
      flex-direction:column;
      gap:7px;
      box-shadow:0 12px 28px rgba(0,0,0,0.45);
      backdrop-filter:blur(22px);
      cursor:pointer;
      position:relative;
      overflow:hidden;
      animation:floatIn .35s ease both;
    }
    .card::before{
      content:"";
      position:absolute;
      inset:-40%;
      background:radial-gradient(circle at 0% 0%, rgba(103,255,242,0.18) 0, transparent 55%);
      opacity:0;
      transition:opacity .25s ease;
      pointer-events:none;
    }
    .card:hover::before{
      opacity:1;
    }
    .card:hover{
      transform:translateY(-6px) translateZ(0);
      box-shadow:0 18px 40px rgba(0,0,0,0.7);
      border-color:rgba(103,255,242,0.7);
    }

    .card-kicker{
      font-size:11px;
      letter-spacing:.16em;
      text-transform:uppercase;
      color:var(--ink-muted);
    }
    .card-title{
      font-size:14px;
      font-weight:600;
    }
    .card-summary{
      font-size:12px;
      color:var(--ink-muted);
    }
    .card-footer{
      margin-top:4px;
      display:flex;
      justify-content:flex-end;
      align-items:center;
      font-size:11px;
      color:var(--ink-muted);
      opacity:.9;
    }

    @media (max-width: 768px){
      body{
        padding:22px 16px 30px;
      }
      .topbar{
        flex-direction:column;
        align-items:flex-start;
      }
      .meta-row{
        flex-direction:column;
        align-items:flex-start;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-title">CyberIntel</div>
        <div class="brand-sub">Live Community CTI Platform.</div>
      </div>
      %%USER_CONTROL%%
    </header>

    <div class="meta-row">
      <div id="storyCount">Loading stories…</div>
      <div id="lastUpdate">Updated —</div>
    </div>

    <main id="grid" class="grid">
      <!-- cards injected here -->
    </main>
  </div>

<script>
(function(){
  const grid = document.getElementById("grid");
  const storyCount = document.getElementById("storyCount");
  const lastUpdate = document.getElementById("lastUpdate");

  function jget(url){
    return fetch(url).then(r => r.json());
  }

  function fmtTime(s){
    try{
      const d = new Date(s);
      return d.toLocaleString();
    }catch(e){
      return s;
    }
  }

  function isRealItem(it){
    const title = (it.title || "").toLowerCase();
    if (!it.link || it.link === "#") return false;
    if (title.includes("placeholder")) return false;
    if (title.includes("no live headlines")) return false;
    return true;
  }

  function render(items){
    const real = items.filter(isRealItem);
    storyCount.textContent = real.length + " stories";
    grid.innerHTML = real.map((it, idx) => `
      <article class="card" style="animation-delay:${idx * 0.02}s" onclick="window.open('${it.link}','_blank')">
        <div class="card-kicker">Live </div>
        <div class="card-title">${it.title}</div>
        <p class="card-summary">${it.summary || ""}</p>
        <div class="card-footer">
          <span>${fmtTime(it.published || "")}</span>
        </div>
      </article>
    `).join("");
  }

  async function load(){
    const data = await jget("/api/news?limit=60");
    lastUpdate.textContent = "Updated " + fmtTime(data.updated);
    render(data.items || []);
  }

  load();
})();
</script>
</body>
</html>
"""

AUTH_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>CyberIntel – %%AUTH_TITLE%%</title>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet">
  <style>
    :root{
      --bg-top:#2A3056;
      --bg-bottom:#294933;
      --accent:#67FFF2;
      --accent-alt:#81EC86;
      --ink:#F6F7FF;
      --ink-muted:#9FB3D2;
      --border-subtle:rgba(255,255,255,0.12);
    }
    *{box-sizing:border-box;margin:0;padding:0}
    body{
      font:14px/1.5 "Poppins",system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Ubuntu,"Helvetica Neue",Arial,sans-serif;
      color:var(--ink);
      min-height:100vh;
      display:flex;
      align-items:center;
      justify-content:center;
      padding:24px;
      background:
        radial-gradient(circle at 0% 0%, rgba(103,255,242,0.22) 0, transparent 55%),
        radial-gradient(circle at 100% 100%, rgba(129,236,134,0.18) 0, transparent 55%),
        linear-gradient(135deg,var(--bg-top),var(--bg-bottom));
    }
    a{color:inherit;text-decoration:none}
    a:hover{text-decoration:underline}
    .card{
      width:100%;
      max-width:420px;
      background:rgba(0,0,0,0.55);
      border-radius:20px;
      padding:22px 22px 20px;
      border:1px solid var(--border-subtle);
      box-shadow:0 18px 40px rgba(0,0,0,0.7);
      backdrop-filter:blur(24px);
    }
    h1{
      font-size:22px;
      margin-bottom:4px;
    }
    .sub{
      font-size:12px;
      color:var(--ink-muted);
      margin-bottom:18px;
    }
    label{
      display:block;
      font-size:12px;
      margin-bottom:4px;
    }
    input{
      width:100%;
      padding:8px 10px;
      border-radius:999px;
      border:1px solid var(--border-subtle);
      background:rgba(0,0,0,0.45);
      color:var(--ink);
      font-family:inherit;
      font-size:13px;
      outline:none;
      margin-bottom:12px;
    }
    input:focus{
      border-color:var(--accent);
      box-shadow:0 0 0 1px rgba(103,255,242,0.8);
    }
    .btn{
      width:100%;
      border:none;
      padding:9px 12px;
      border-radius:999px;
      background:linear-gradient(135deg,var(--accent),var(--accent-alt));
      color:#021118;
      font-weight:600;
      font-size:13px;
      cursor:pointer;
      margin-top:4px;
      box-shadow:0 14px 32px rgba(0,0,0,0.6);
      transition:transform .15s ease, box-shadow .15s ease, filter .15s ease;
    }
    .btn:hover{
      transform:translateY(-1px);
      box-shadow:0 18px 40px rgba(0,0,0,0.75);
      filter:brightness(1.05);
    }
    .btn:active{
      transform:translateY(0);
      box-shadow:0 10px 24px rgba(0,0,0,0.6);
    }
    .muted{
      margin-top:10px;
      font-size:11px;
      color:var(--ink-muted);
    }
    .muted a{color:var(--accent)}
    .back-link{
      display:inline-flex;
      align-items:center;
      gap:4px;
      margin-bottom:10px;
      font-size:12px;
      color:var(--ink-muted);
    }
  </style>
</head>
<body>
  <div class="card">
    <a class="back-link" href="/">
      <span>←</span><span>Back to tiles</span>
    </a>
    <h1>%%AUTH_TITLE%%</h1>
    <p class="sub">%%AUTH_SUB%%</p>
    <form method="post" action="/auth">
      <label for="username">Username</label>
      <input id="username" name="username" required value="%%USERNAME%%" />

      <label for="email">Email</label>
      <input id="email" name="email" type="email" required value="%%EMAIL%%" />

      <label for="password">Password</label>
      <input id="password" name="password" type="password" required />

      <button class="btn" type="submit">Save</button>
    </form>
    <p class="muted">
      Passwords are stored with a basic hash for demo purposes only. Do not reuse
      sensitive production credentials here.
    </p>
  </div>
</body>
</html>
"""

# ------------------------------- Routes --------------------------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = _current_user(request)
    if user:
        initials = (user.get("username") or user.get("email") or "?")[:1].upper()
        user_html = f"""
        <div class="user-chip">
          <div class="user-avatar">{initials}</div>
          <div class="user-meta">
            <div class="user-name">{user.get('username') or 'User'}</div>
            <div class="user-email">{user.get('email')}</div>
          </div>
          <div class="user-actions">
            <a href="/auth">Account</a>
            <a href="/logout">Logout</a>
          </div>
        </div>
        """
    else:
        user_html = """
        <a class="auth-btn" href="/auth">
          <span class="icon">⟶</span>
          <span>Login / Register</span>
        </a>
        """

    html = INDEX_HTML.replace("%%USER_CONTROL%%", user_html)
    return HTMLResponse(html)


@app.get("/auth", response_class=HTMLResponse)
def auth_form(request: Request):
    user = _current_user(request)
    if user:
        title = "Account settings"
        sub = "Update your profile or change your password."
        username = user.get("username") or ""
        email = user.get("email") or ""
    else:
        title = "Login / Register"
        sub = "Create an account or update your details to receive CyberIntel updates."
        username = ""
        email = ""

    html = (
        AUTH_HTML.replace("%%AUTH_TITLE%%", title)
        .replace("%%AUTH_SUB%%", sub)
        .replace("%%USERNAME%%", username)
        .replace("%%EMAIL%%", email)
    )
    return HTMLResponse(html)


@app.post("/auth")
def auth_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
):
    user, is_new = _register_or_update_user(username, email, password)
    if is_new:
        _send_welcome_email(user)

    resp = RedirectResponse("/", status_code=302)
    # "logged in" – set cookie with email
    resp.set_cookie(
        SESSION_COOKIE_NAME,
        user["email"],
        max_age=60 * 60 * 24 * 30,  # 30 days
        httponly=False,
    )
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


# ------------------------------- Main ----------------------------------

if __name__ == "__main__":
    import uvicorn
    _prewarm()
    uvicorn.run(app, host="127.0.0.1", port=8000)
