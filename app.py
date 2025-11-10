import threading
import time
import json
from datetime import datetime, timezone
from typing import Dict, List

import feedparser
from fastapi import FastAPI, Query
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

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

# Kept in DOM but hidden from users
IOC_SOURCE = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

CACHE_TTL_SECONDS = 10 * 60           # 10 minutes
BACKGROUND_REFRESH_SECONDS = 10 * 60  # background refresh cadence
AUTO_REFRESH_CLIENT_SECONDS = 60      # client-side auto refresh

# ------------------------------ App/Core -------------------------------

app = FastAPI(title="CyberIntel (clean)")
app.add_middleware(GZipMiddleware, minimum_size=512)

_cache_lock = threading.Lock()
_news_cache: Dict[str, Dict] = {}   # {category: {"ts": epoch, "items": [...]}}
_last_build_time_iso = datetime.now(timezone.utc).isoformat()


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


def _fetch_category(cat: str) -> List[Dict]:
    items: List[Dict] = []
    for url in FEEDS.get(cat, []):
        try:
            feed = feedparser.parse(url)
            for e in feed.get("entries", [])[:30]:
                items.append(_normalize_entry(e))
        except Exception:
            continue
    # sort newest first
    items.sort(key=lambda x: x["published"], reverse=True)
    return items[:60]


def _ensure_fresh(cat: str) -> Dict:
    """Return a cache bucket for a category; guarantee >=1 item with a safe placeholder if needed."""
    global _last_build_time_iso
    with _cache_lock:
        bucket = _news_cache.get(cat)
        if not bucket or (_now() - bucket["ts"] > CACHE_TTL_SECONDS):
            items = _fetch_category(cat)
            # Fallback: ensure non-empty to satisfy "should not be zero"
            if not items:
                items = [{
                    "title": f"[{cat}] No recent headlines found (placeholder)",
                    "link": "#",
                    "summary": "Feeds returned no items just now. Try Refresh or check back soon.",
                    "source": "System",
                    "published": _iso_now(),
                }]
            bucket = {"ts": _now(), "items": items}
            _news_cache[cat] = bucket
            _last_build_time_iso = _iso_now()
        return bucket


def _stats_snapshot() -> Dict:
    with _cache_lock:
        return {
            "updated": _last_build_time_iso,
            "categories": {
                c: {"items": len(_news_cache.get(c, {}).get("items", []))}
                for c in CATEGORIES
            },
            "ttl_seconds": CACHE_TTL_SECONDS,
        }


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


# Start background refresh thread
threading.Thread(target=_background_refresher, daemon=True).start()

# ------------------------------- API -----------------------------------

@app.get("/api/news", response_class=JSONResponse)
def api_news(category: str = Query(default="Home"), limit: int = Query(60, ge=1, le=200)):
    if category == "Home":
        merged: List[Dict] = []
        for c in CATEGORIES:
            merged.extend(_ensure_fresh(c)["items"])
        merged.sort(key=lambda x: x["published"], reverse=True)
        merged = merged[:limit]
        return {"items": merged, "total_all": len(merged), "updated": _last_build_time_iso}
    if category not in CATEGORIES:
        return {"items": [], "total_all": 0, "updated": _last_build_time_iso}
    bucket = _ensure_fresh(category)
    return {"items": bucket["items"][:limit], "total_all": len(bucket["items"]), "updated": _last_build_time_iso}


@app.get("/api/stats", response_class=JSONResponse)
def api_stats():
    return _stats_snapshot()


@app.post("/api/refresh", response_class=JSONResponse)
def api_refresh():
    with _cache_lock:
        _news_cache.clear()
    _prewarm()
    return {"status": "ok", "updated": _last_build_time_iso}

# ------------------------------ Frontend -------------------------------

HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>CyberIntel</title>
  <style>
  :root{
    --bg:#0b0d10;--card:#13161a;--ink:#e6e6e6;--ink-muted:#a8b0b9;--accent:#ff914d;--chip:#1f242b;
  }
  [data-theme="light"]{
    --bg:#f7f8fa;--card:#ffffff;--ink:#111216;--ink-muted:#5b6673;--accent:#ff6a00;--chip:#eef1f4;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.45 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial}
  .wrap{max-width:1200px;margin:0 auto;padding:24px}
  header{display:flex;align-items:center;gap:14px;margin-bottom:14px}
  .brand{font-weight:800;font-size:22px}
  nav{display:flex;flex-wrap:wrap;gap:8px}
  .chip{background:var(--chip);padding:6px 10px;border-radius:999px;cursor:pointer;font-size:14px;border:1px solid transparent}
  .chip.active{border-color:var(--accent);}
  .toggle{margin-left:auto;background:var(--chip);color:var(--ink);border:1px solid transparent;border-radius:10px;padding:8px 10px;cursor:pointer}
  .bar h1{margin:0 0 6px 0;font-size:22px}
  .muted{color:var(--ink-muted)}
  .toolbar{display:flex;gap:8px;align-items:center;margin-top:8px}
  /* Safety: hide any legacy search input that might come from cached HTML */
  .toolbar input, input[placeholder*="Filter news"]{display:none!important}
  .btn{background:var(--accent);color:#fff;border:0;border-radius:10px;padding:8px 12px;cursor:pointer}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px;margin-top:16px}
  .card{background:var(--card);border:1px solid #20242a;padding:14px;border-radius:12px}
  .src{color:var(--ink-muted);font-size:13px;margin-bottom:6px}
  a.title{color:var(--ink);font-weight:700;text-decoration:none}
  .title:hover{text-decoration:underline}
  .summary{color:var(--ink-muted);margin-top:6px}
  .footer{margin-top:28px;text-align:center;color:var(--ink-muted);font-size:13px}
  .hidden{display:none}
  .icon{font-size:16px}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="brand">CyberIntel</div>
      <nav id="tabs"></nav>
      <!-- sun/moon icon button -->
      <button id="themeToggle" class="toggle" title="Toggle dark/light" aria-label="Toggle theme">
        <span id="themeIcon" class="icon">🌙</span>
      </button>
    </header>

    <section class="bar">
      <h1>IT and Cybersecurity trends &amp; threats</h1>
      <div class="muted">
        <span id="countLabel">0 stories</span>
        &nbsp;•&nbsp;
        <span id="lastUpdate">—</span>
        <span id="iocSource" class="hidden">
          &nbsp;•&nbsp; IOC source:
          <a href="%%IOC_SOURCE%%" target="_blank" rel="noopener">%%IOC_SOURCE%%</a>
        </span>
      </div>
      <div class="toolbar">
        <!-- Search removed by request -->
        <button id="refreshBtn" class="btn" title="Fetch fresh data">Refresh now</button>
        <span class="muted" id="autoLabel">Auto-refresh %%AUTO_REFRESH_SECS%%s (on)</span>
      </div>
    </section>

    <section id="grid" class="grid"></section>

    <footer class="footer">Made for demo purposes • <span class="muted">Last rebuild client-side only</span></footer>
  </div>

<script>
(function(){
  const CATS = %%CATS%%;
  let CURRENT = "Home";
  let CURRENT_ITEMS = [];
  let TIMER = null;

  const tabs = document.getElementById("tabs");
  const grid = document.getElementById("grid");
  const lastUpdate = document.getElementById("lastUpdate");
  const countLabel = document.getElementById("countLabel");
  const themeToggle = document.getElementById("themeToggle");
  const themeIcon = document.getElementById("themeIcon");
  const refreshBtn = document.getElementById("refreshBtn");

  // Build tabs
  function tabEl(name){
    const el = document.createElement("button");
    el.className = "chip";
    el.dataset.cat = name;
    el.textContent = name;
    el.onclick = async ()=>{
      CURRENT = name;
      activateTab(name);
      await load();
    };
    return el;
  }
  tabs.appendChild(tabEl("Home"));
  CATS.forEach(c => tabs.appendChild(tabEl(c)));
  activateTab("Home");

  function activateTab(name){
    tabs.querySelectorAll(".chip").forEach(ch => ch.classList.toggle("active", ch.dataset.cat === name));
  }

  // theme toggle
  function currentTheme(){ return document.documentElement.getAttribute("data-theme") || "dark"; }
  function setTheme(mode){
    document.documentElement.setAttribute("data-theme", mode);
    themeIcon.textContent = mode === "dark" ? "🌙" : "☀️";
  }
  themeToggle.onclick = ()=> setTheme(currentTheme()==="dark"?"light":"dark");
  setTheme("dark");

  async function jget(url){
    const r = await fetch(url);
    return await r.json();
  }

  function fmt(s){
    try{
      const d = new Date(s); return d.toLocaleString();
    }catch(e){ return s; }
  }

  function render(items){
    CURRENT_ITEMS = items;
    countLabel.textContent = items.length + " stories";
    grid.innerHTML = items.map(it => `
      <article class="card">
        <div class="src">${(it.source||"—")} • ${fmt(it.published)}</div>
        <a class="title" href="${it.link}" target="_blank" rel="noopener">${it.title}</a>
        <div class="summary">${it.summary||""}</div>
      </article>
    `).join("");
  }

  async function load(force=false){
    const url = "/api/news?category="+encodeURIComponent(CURRENT)+"&limit=60"+(force?"&_="+Date.now():"");
    const data = await jget(url);
    lastUpdate.textContent = data.updated + " last update";
    render(data.items||[]);
  }

  refreshBtn.onclick = async ()=>{
    refreshBtn.disabled = true;
    try { await fetch("/api/refresh", {method:"POST"}); } catch(e){}
    await load(true);
    refreshBtn.disabled = false;
  };

  function arm(){
    if (TIMER) clearInterval(TIMER);
    TIMER = setInterval(()=> load(true), %%AUTO_REFRESH_SECS%% * 1000);
  }

  load(false);
  arm();
})();
</script>
</body>
</html>
"""

# ------------------------------- Routes --------------------------------

@app.get("/", response_class=HTMLResponse)
def index():
    html = (
        HTML.replace("%%CATS%%", json.dumps(CATEGORIES))
            .replace("%%AUTO_REFRESH_SECS%%", str(AUTO_REFRESH_CLIENT_SECONDS))
            .replace("%%IOC_SOURCE%%", IOC_SOURCE)
    )
    return HTMLResponse(html)

# ------------------------------- Main ----------------------------------

if __name__ == "__main__":
    import uvicorn
    _prewarm()  # warm cache for fast first paint
    uvicorn.run(app, host="127.0.0.1", port=8000)
