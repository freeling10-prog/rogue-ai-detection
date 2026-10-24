"""v6 "Deep-Cover & Frontier Evasion": honeypot-side building blocks.

* **Challenge-bound beacon.** Every HTML page carries a per-page, per-time-bucket challenge (HMAC of page path + 5-minute bucket under
  the server key; no client identifier) and a tiny off-screen layout probe whose size is derived from the challenge.  The inline
  beacon script combines the challenge with the probe's *rendered* size, so only a client that runs our script in a layout engine
  (or re-implements both) can produce the proof.  The beacon POST carries the proof plus five booleans; the server keeps ONLY the
  six booleans (``challenge_proof_ok`` computed server-side).  A canned / replayed / invalid proof is ``beacon_forged``.
* **Load-bearing provenance cursors.** /kb/ detail + pagination and the paginated API route need a ``cursor`` / ``page_ref`` token.
  Tokens are HMAC-signed and carry their provenance: ``prov.html.<mac>`` in links on our HTML pages, ``prov.schema.<mac>`` in
  /openapi.json, /llms.txt and POST /mcp results.  A request without a valid cursor gets ``400 Missing Required Cursor``; every HTML link
  a person can click carries a valid html cursor, so normal navigation never sees the 400.
* **DOM-visual order inversion** markup for / and /kb/ (the archive link is first in the DOM, rendered last with CSS ``order:99``).
* **LRU rate limiter** (OrderedDict; evicts the oldest 25% of keys when full instead of resetting everything).
* **CSP** for honeypot HTML responses.

HONEST LIMITS: a client that re-implements the script (parses the meta tag and the probe style) can forge the proof; the cursor trap
only catches clients that use a schema-served token in a browsing session; DOM-order inversion catches DOM-order iteration, not
pixel-space agents; everything was tested only against the same author's simulated clients.
"""
from __future__ import annotations

import hmac
import re
import threading
from collections import OrderedDict
from typing import Callable, Optional

Digest = Callable[[str], str]

# NOTE (v6 review): the requested policy had script-src 'unsafe-inline' only.  That would stop a compliant browser from fetching
# /static/site.js, which the asset-kind and js_assets_fetched logic relies on (people would look like they never fetch scripts).
# 'self' is therefore added to script-src; everything else is exactly as requested.  default-src 'self' keeps the beacon fetch()
# (connect-src falls back to default-src) same-origin only.
HONEYPOT_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; "
                "object-src 'none'; base-uri 'none'")
CHALLENGE_BUCKET_S = 300
CHALLENGE_MAX_AGE_BUCKETS = 288       # 24 h: a tab left open for hours must not turn a person's click into "beacon_forged"
BEACON_BOOLS = ("webdriver_present", "pointer_trail_seen", "dom_automation_props", "kinematic_dwell_ok", "inertial_scroll_ok")
BEACON_FIELDS = ("challenge_proof_ok",) + BEACON_BOOLS            # exactly what is stored
INVERSION_PATH = "/kb/archive/diagnostic"
CURSOR_RE = re.compile(r"^prov\.(html|schema)\.([0-9a-f]{12})$")
LLM_PATH = "/v1/chat/completions"
LLM_MAX_BYTES = 16 * 1024
LLM_RATE_PER_MIN = 10


class LRURateLimiter:
    """Per-key sliding one-minute window.  At ``max_keys`` the OLDEST 25% of keys are evicted (v5 review: no full reset)."""

    def __init__(self, per_min: int, max_keys: int = 2000) -> None:
        self.per_min, self.max_keys = per_min, max_keys
        self.windows: "OrderedDict[str, list[float]]" = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str, now: float) -> bool:
        with self._lock:
            window = [t for t in self.windows.pop(key, []) if now - t < 60.0]
            if len(self.windows) >= self.max_keys:
                for _ in range(max(1, self.max_keys // 4)):
                    self.windows.popitem(last=False)
            ok = len(window) < self.per_min
            if ok:
                window.append(now)
            self.windows[key] = window              # (re)inserted at the end = most recently used
            return ok


def _mac(secret_digest: Digest, label: str, n: int) -> str:
    return str(secret_digest(label))[:n]


def challenge(digest: Digest, path: str, bucket: int) -> str:
    """16 hex chars: the 7-hex time bucket (so verification needs ONE HMAC, not one per candidate bucket) + 9 hex of
    HMAC(server key, path + bucket).  Same value for every client on that page in that bucket: no client identifier."""
    return f"{bucket % (1 << 28):07x}" + _mac(digest, f"chal:{path}:{bucket}", 9)


def probe_size(chal: str) -> tuple[int, int]:
    """Rendered size of the off-screen probe, derived from the challenge (so the proof changes per page and bucket)."""
    return 20 + int(chal[7:9], 16) % 40, 8 + int(chal[9:11], 16) % 16


def expected_proof(chal: str) -> str:
    w, h = probe_size(chal)
    return f"{chal}.{w}x{h}"


def verify_proof(digest: Digest, page: str, proof: str, now_ts: float) -> bool:
    if not isinstance(page, str) or not isinstance(proof, str) or not page.startswith("/") or len(page) > 300 or len(proof) > 64:
        return False
    if not re.fullmatch(r"[0-9a-f]{16}\.\d{1,4}x\d{1,4}", proof):
        return False
    now_b = int(now_ts // CHALLENGE_BUCKET_S)
    b = now_b - ((now_b - int(proof[:7], 16)) % (1 << 28))            # undo the 28-bit wrap
    if not 0 <= now_b - b <= CHALLENGE_MAX_AGE_BUCKETS:
        return False                                                   # from the future, or older than 24 h
    return hmac.compare_digest(expected_proof(challenge(digest, page, b)), proof)


def challenge_html(digest: Digest, path: str, now_ts: float) -> str:
    chal = challenge(digest, path, int(now_ts // CHALLENGE_BUCKET_S))
    w, h = probe_size(chal)
    return (f"<meta name='aw-challenge' content='{chal}'>"
            f"<div id='aw-probe' aria-hidden='true' style='position:absolute;left:-9999px;top:0;width:{w}px;height:{h}px'></div>")


def cursor(digest: Digest, prov: str, target: str) -> str:
    """HMAC-signed, provenance-carrying cursor for *target* (a path, or '/kb/?page=N' for pagination)."""
    return f"prov.{prov}.{_mac(digest, f'cursor:{prov}:{target}', 12)}"


def check_cursor(digest: Digest, token: Optional[str], target: str) -> Optional[str]:
    """'html' | 'schema' when *token* is a valid cursor for *target*, else None."""
    m = CURSOR_RE.match(token or "")
    if not m:
        return None
    prov = m.group(1)
    return prov if hmac.compare_digest(cursor(digest, prov, target), token or "") else None


def inversion_list(inverted_html: str, normal_html: str) -> str:
    """DOM-visual order inversion: the diagnostic link is FIRST in the DOM and rendered LAST (``order:99``)."""
    return ("<ul class='aw-nav' style='display:flex;flex-direction:column;list-style:none;padding:0;margin:0'>"
            f"<li style='order:99'>{inverted_html}</li><li style='order:1'>{normal_html}</li></ul>")


def inversion_link() -> str:
    return f"<a href='{INVERSION_PATH}' style='font-size:11px;color:#888'>Diagnostic archive</a>"


# Inline, same-origin beacon script (v6).  On a click on an internal link it POSTs ONE JSON object: the challenge proof (page meta +
# rendered probe size), the page path (for proof verification only; not stored) and five booleans.  No identifiers.
def beacon_script(path: str) -> str:
    """Inline beacon.  ``kinematic_dwell_ok`` is true when press duration >= 12 ms AND the recent pointer
    path is non-collinear (max cross-product deviation > 1 px).  Uses pointerdown/up (Playwright) as well
    as mouse events.

    Dwell < 12 ms is *inconclusive* (JSON null), not false, when ``pointerType === "touch"`` / TouchEvent
    is present, or when OS-level tap-to-click produces 0–4 ms dwell without other automation signals
    (mobile and trackpad humans commonly land in that band). Short dwell *with* webdriver / DOM
    automation props remains false. ``vlm_quantized_interaction`` still requires
    ``kinematic_dwell_ok is False`` (null does not corroborate) plus bad scroll on >= vlm_min_beacons
    (or an inversion hit), so a touch / trackpad user alone is not labelled VLM.
    """
    # Built without nested quote hell: the only tricky bit is a[href^="/"].
    href_sel = "a[href^=\"/\"]"
    return (
        "<script>(function(){var c=document.querySelector('meta[name=aw-challenge]');c=c?c.content:'';"
        "var m=0,P=[],dn=0,dw=-1,W=[],sc=0,pt='';"
        "function mv(e){m=1;if(e.clientX!=null){P.push([e.clientX,e.clientY]);if(P.length>10)P.shift()}}"
        "addEventListener('pointermove',mv,{passive:true});addEventListener('mousemove',mv,{passive:true});"
        "addEventListener('touchmove',function(){m=1},{passive:true});"
        "addEventListener('touchstart',function(){m=1},{passive:true});"
        "function pd(e){dn=performance.now();if(e&&e.pointerType)pt=e.pointerType}"
        "function pu(){if(dn)dw=performance.now()-dn}"
        "addEventListener('pointerdown',pd,true);addEventListener('pointerup',pu,true);"
        "addEventListener('mousedown',pd,true);addEventListener('mouseup',pu,true);"
        "addEventListener('wheel',function(e){sc=1;W.push(Math.abs(e.deltaY));if(W.length>12)W.shift()},{passive:true});"
        "function nc(){if(P.length<3)return false;var max=0;for(var i=2;i<P.length;i++){var a=P[i-2],b=P[i-1],d=P[i];"
        "var v=Math.abs((b[0]-a[0])*(d[1]-a[1])-(b[1]-a[1])*(d[0]-a[0]));if(v>max)max=v}return max>1}"
        "function inert(){if(!sc||W.length<3)return true;var dec=0,flat=true;for(var i=1;i<W.length;i++){if(W[i]<W[i-1])dec++;"
        "if(W[i]!==W[0])flat=false}return !flat&&dec>=(W.length-1)/3}"
        "function dwellOk(p){if(dw<0)return null;if(dw>=12)return nc();var touch=pt==='touch'||pt==='pen';"
        "try{if(!touch&&pt!=='mouse'&&(('ontouchstart'in window)||(navigator.maxTouchPoints>0)))touch=true}catch(_){}"
        "if(touch)return null;if(dw<=4&&!p&&navigator.webdriver!==true)return null;return false}"
        "addEventListener('click',function(e){var t=e.target,a=t&&t.closest&&t.closest('" + href_sel + "');if(!a)return;"
        "var p=false;try{for(var k in window){if(/^(__playwright|__pw|cdc_|\\$cdc_|__nightmare|_phantom|callPhantom|__selenium|__webdriver)/.test(k)){p=true;break}}}catch(_){}"
        "var pr=document.getElementById('aw-probe');var proof=c+'.'+(pr?pr.offsetWidth+'x'+pr.offsetHeight:'0x0');"
        "try{fetch('/api/v1/telemetry/nav',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',keepalive:true,"
        "body:JSON.stringify({proof:proof,page:location.pathname,webdriver_present:navigator.webdriver===true,pointer_trail_seen:!!m,"
        "dom_automation_props:p,kinematic_dwell_ok:dwellOk(p),inertial_scroll_ok:inert()})})}catch(_){}},true)})();</script>"
    )



AUTONOMY_RE = re.compile(r"\b(loop|keep going|continue until|until (?:done|complete|finished)|autonomous(?:ly)?|without (?:asking|confirmation|"
                         r"human)|repeat until|never stop|run indefinitely|do not stop|self-?direct)", re.I)


def length_bucket(n: int) -> str:
    return "0" if n == 0 else "1-200" if n <= 200 else "201-1000" if n <= 1000 else "1001-4000" if n <= 4000 else ">4000"
