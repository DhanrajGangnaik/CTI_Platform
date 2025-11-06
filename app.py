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
        "https://www.databreaches.net/feed/",
    ],
    "APT": [
        "https://thehackernews.com/feeds/posts/default/-/APT",
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

# Kept in DOM but hidden from users (requirement)
IOC_SOURCE = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

CACHE_TTL_SECONDS = 10 * 60           # 10 minutes
BACKGROUND_REFRESH_SECONDS = 10 * 60  # background refresh cadence
AUTO_REFRESH_CLIENT_SECONDS = 60      # client-side auto refresh

# ------------------------------ App/Core -------------------------------

app = FastAPI(title="CyberIntel (minimal)")
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
    if "published_parsed" in entry and entry.published_parsed:
        published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc).isoformat()
    else:
        published = _iso_now()
    return {
        "title": title or "(no title)",
        "link": link,
        "summary": summary,
        "source": source,
        "published": published,
    }


def _fetch_category(cat: str) -> List[Dict]:
    items: List[Dict] = []
    for url in FEEDS.get(cat, []):
        try:
            parsed = feedparser.parse(url)
            for e in parsed.entries[:30]:
                items.append(_normalize_entry(e))
        except Exception:
            continue
    # dedupe by link; newest first
    seen = set()
    out: List[Dict] = []
    for it in sorted(items, key=lambda x: x["published"], reverse=True):
        if it["link"] in seen:
            continue
        seen.add(it["link"])
        out.append(it)
    return out[:60]


def _ensure_fresh(cat: str) -> Dict:
    with _cache_lock:
        bucket = _news_cache.get(cat)
        if not bucket or (_now() - bucket["ts"] > CACHE_TTL_SECONDS):
            bucket = {"ts": _now(), "items": _fetch_category(cat)}
            _news_cache[cat] = bucket
        return bucket


def _stats_snapshot() -> Dict:
    with _cache_lock:
        stats = {c: len(_news_cache.get(c, {}).get("items", [])) for c in CATEGORIES}
        stats["__all"] = sum(stats.values())
        return stats


def _prewarm() -> None:
    for c in CATEGORIES:
        try:
            _ensure_fresh(c)
        except Exception:
            pass
    global _last_build_time_iso
    _last_build_time_iso = _iso_now()


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

# ------------------------------- HTML ----------------------------------

# Minimal CSS colour palette:
# - Branding orange: #E85002
# - Primary black:   #000000
# - White:           #F9F9F9
# - Dark gray:       #333333
# - Gray:            #646464
# - Light gray:      #A7A7A7
HTML = r"""
<!doctype html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>CyberIntel • CTI News</title>
  <style>
  :root{
    /* Light theme tokens */
    --bg: #F9F9F9;
    --panel: #FFFFFF;
    --ink: #000000;
    --ink-muted: #646464;
    --border: #A7A7A7;
    --accent: #E85002;        /* branding orange */
    --accent-600: #C10801;
    --accent-700: #F16001;
    --radius: 10px;
  }
  [data-theme="dark"]{
    /* Dark theme tokens */
    --bg: #000000;
    --panel: #111111;
    --ink: #F9F9F9;
    --ink-muted: #A7A7A7;
    --border: #333333;
    --accent: #E85002;
    --accent-600: #C10801;
    --accent-700: #F16001;
  }

  html,body{margin:0;padding:0;background:var(--bg);color:var(--ink);
            font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif}
  .wrap{max-width:1100px;margin:0 auto;padding:20px 16px 60px}
  header{display:flex;gap:12px;align-items:center;margin-bottom:10px}
  .brand{font-weight:800;font-size:24px}
  #tabs{display:flex;gap:8px;flex-wrap:wrap;margin-left:8px}
  .tab{display:inline-flex;gap:8px;align-items:center;padding:8px 12px;border:1px solid var(--border);
       border-radius:999px;text-decoration:none;color:var(--ink-muted);background:transparent}
  .tab.active{color:var(--ink);border-color:var(--accent)}
  .pill{font-size:12px;color:#fff;background:var(--accent);padding:2px 8px;border-radius:999px}
  .toggle{margin-left:auto;border:1px solid var(--border);background:transparent;color:var(--ink);
          border-radius:999px;padding:8px 10px;cursor:pointer;line-height:1}
  .toggle:hover{border-color:var(--accent);}

  .bar{border:1px solid var(--border);border-radius:var(--radius);background:var(--panel);padding:14px;margin-top:8px}
  .bar h1{font-size:20px;margin:0 0 6px 0}
  .muted{color:var(--ink-muted);font-size:13px}
  .toolbar{display:flex;gap:10px;align-items:center;margin-top:8px}
  .input{flex:1;border:1px solid var(--border);background:transparent;color:var(--ink);padding:10px 12px;border-radius:8px}
  .btn{border:1px solid var(--accent);background:var(--accent);color:#fff;padding:10px 14px;border-radius:8px;cursor:pointer;font-weight:600}
  .btn:hover{background:var(--accent-600);border-color:var(--accent-600)}
  .btn:active{background:var(--accent-700);border-color:var(--accent-700)}

  .grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-top:14px}
  @media (max-width:920px){.grid{grid-template-columns:1fr}}
  .card{border:1px solid var(--border);background:var(--panel);border-radius:var(--radius);padding:14px}
  .src{color:var(--ink-muted);font-size:13px}
  .title{display:block;margin-top:6px;font-weight:700;color:var(--ink);text-decoration:none}
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
        <input id="filter" class="input" placeholder="Filter news (title, source, summary)…"/>
        <button id="refreshBtn" class="btn" title="Fetch fresh data">Refresh now</button>
        <span class="muted" id="autoLabel">Auto-refresh %%AUTO_REFRESH_SECS%%s (on)</span>
      </div>
    </section>

    <section id="grid" class="grid"></section>
    <div class="footer">© CyberIntel • Live Community CTI Sharing Platform </div>
  </div>

<script>
(function(){
  // -------- Theme (with icon text change) --------
  const root = document.documentElement;
  const icon = document.getElementById("themeIcon");
  const saved = localStorage.getItem("theme") || "dark";
  root.setAttribute("data-theme", saved);
  icon.textContent = saved === "dark" ? "🌙" : "☀️";

  document.getElementById("themeToggle").onclick = () => {
    const next = root.getAttribute("data-theme")==="dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
    icon.textContent = next === "dark" ? "🌙" : "☀️";
  };

  // -------- Tabs --------
  const CATS = %%CATS%%; // injected JSON array
  let CURRENT = "Home";

  function pill(n){ return '<span class="pill">'+n+'</span>'; }

  function buildTabs(stats){
    const tabs = document.getElementById("tabs");
    const labels = ["Home"].concat(CATS);
    tabs.innerHTML = labels.map(l=>{
      const n = l==="Home" ? (stats.__all||0) : (stats[l]||0);
      const active = (CURRENT===l) ? " active" : "";
      return '<a href="#" class="tab'+active+'" data-cat="'+l+'">'+l+' '+pill(n)+'</a>';
    }).join("");
    Array.from(tabs.querySelectorAll("a")).forEach(a=>{
      a.onclick = (e)=>{ e.preventDefault(); CURRENT=a.dataset.cat; load(false); };
    });
  }

  // -------- Data/Render --------
  const grid = document.getElementById("grid");
  const filter = document.getElementById("filter");
  const countLabel = document.getElementById("countLabel");
  const lastUpdate = document.getElementById("lastUpdate");
  const refreshBtn = document.getElementById("refreshBtn");

  let TIMER = null;
  let CURRENT_ITEMS = [];

  const fmt = x => { try { return new Date(x).toLocaleString(); } catch(e){ return x; } };

  function render(items){
    CURRENT_ITEMS = items;
    const q = (filter.value||"").toLowerCase();
    const list = items.filter(it=>{
      const hay = (it.title+" "+(it.source||"")+" "+(it.summary||"")).toLowerCase();
      return hay.includes(q);
    });
    countLabel.textContent = list.length + " stories";
    grid.innerHTML = list.map(it => `
      <article class="card">
        <div class="src">${(it.source||"—")} • ${fmt(it.published)}</div>
        <a class="title" href="${it.link}" target="_blank" rel="noopener">${it.title}</a>
        <div class="summary">${it.summary||""}</div>
      </article>
    `).join("");
  }

  async function jget(url){
    const r = await fetch(url, {cache:"no-store"});
    return await r.json();
  }

  async function load(force){
    const stats = await jget("/api/stats");
    buildTabs(stats);

    const url = "/api/news?category="+encodeURIComponent(CURRENT)+"&limit=60"+(force?"&_="+Date.now():"");
    const data = await jget(url);
    lastUpdate.textContent = data.updated + " last update";
    render(data.items||[]);
  }

  // small debounce on filter
  let filTimer = null;
  filter.oninput = ()=>{
    clearTimeout(filTimer);
    filTimer = setTimeout(()=> render(CURRENT_ITEMS), 120);
  };

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
  