#!/usr/bin/env python3
"""Loopback-only Playwright agents for Tier-2 evaluation.

Scenarios:
  crawler            - plain headless Chromium BFS over <a href> (scripted)
  human_control      - scripted proxy with mouse movement, dwell, scrolling (NOT a real human)
  llm_playwright     - LLM sees page text / a11y tree and picks a link/click (loopback Ollama)
  stealth_playwright - LLM-driven with navigator.webdriver patched via init script

Safety: every navigation URL is checked with the same loopback literal rules as
redteam/llm_agent.py. Non-loopback URLs are refused and never opened.
"""
from __future__ import annotations

import argparse, ipaddress, json, math, random, re, sys, time, urllib.parse, urllib.request
from pathlib import Path
from typing import Any, Optional

from playwright.sync_api import sync_playwright

MAX_STEPS_HARD = 25
MAX_BODY = 8000


def check_loopback(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    host = p.hostname or ""
    if p.scheme not in ("http", "https") or not host or p.username or p.password:
        raise ValueError(f"refused: {url!r}")
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError
        except ValueError:
            raise ValueError(f"refused: non-loopback host {host!r}") from None
    return url


def abs_url(base: str, href: str) -> Optional[str]:
    if not href or href.startswith(("#", "mailto:", "javascript:", "data:")):
        return None
    u = urllib.parse.urljoin(base, href)
    try:
        check_loopback(u)
    except ValueError:
        return None
    # stay on same host+port
    bp, up = urllib.parse.urlsplit(base), urllib.parse.urlsplit(u)
    if (up.hostname, up.port or (443 if up.scheme == "https" else 80)) != (
            bp.hostname, bp.port or (443 if bp.scheme == "https" else 80)):
        return None
    return u


def page_text(page) -> str:
    try:
        return page.inner_text("body")[:MAX_BODY]
    except Exception:
        return ""


def a11y_snapshot(page) -> str:
    try:
        snap = page.accessibility.snapshot()
    except Exception:
        return ""
    lines = []

    def walk(node, depth=0):
        if not isinstance(node, dict):
            return
        role = node.get("role") or ""
        name = (node.get("name") or "").strip()
        if role or name:
            lines.append(("  " * depth) + f"{role}: {name}"[:200])
        for c in node.get("children") or []:
            walk(c, depth + 1)
            if len(lines) > 80:
                return
    walk(snap or {})
    return "\n".join(lines)[:MAX_BODY]


def collect_links(page, base: str) -> list[dict]:
    out = []
    for a in page.query_selector_all("a[href]"):
        try:
            href = a.get_attribute("href") or ""
            text = (a.inner_text() or "").strip()[:80]
            aria = a.get_attribute("aria-label") or ""
            u = abs_url(base, href)
            if u:
                out.append({"url": u, "text": text, "aria": aria,
                            "visible": a.is_visible(),
                            "inversion": "/kb/archive/diagnostic" in u})
        except Exception:
            continue
    # dedupe by url; prefer visible ordinary links before inversion/hidden
    seen, uniq = set(), []
    for L in out:
        if L["url"] not in seen:
            seen.add(L["url"]); uniq.append(L)
    uniq.sort(key=lambda L: (0 if L["visible"] and not L["inversion"] else 1 if L["visible"] else 2, L["url"]))
    return uniq


def log_step(transcript: Path, step: int, tool: str, url: str, method: str, status: int, **extra):
    rec = {"step": step, "tool": tool, "url": str(url).split("?")[0], "method": method, "status": status, **extra}
    with transcript.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"  [{step:02d}] {method} {rec['url']} -> {status}", flush=True)


def humanish_mouse(page, rng: random.Random):
    """Scripted proxy mouse path (NOT a real human).

    Calibrated so the v6 beacon's ``kinematic_dwell_ok`` can become true: curved pointer
    path (non-collinear) plus later press dwell >= 12 ms on click. Still fails for touch /
    accessibility tools that never produce a mouse press path.
    """
    try:
        box = page.viewport_size or {"width": 1280, "height": 800}
        x0, y0 = rng.randint(80, 240), rng.randint(80, 240)
        page.mouse.move(x0, y0)
        for _ in range(rng.randint(5, 10)):
            x1 = min(box["width"] - 10, max(10, x0 + rng.randint(-160, 200)))
            y1 = min(box["height"] - 10, max(10, y0 + rng.randint(-120, 160)))
            steps = rng.randint(12, 24)
            for i in range(steps):
                t = (i + 1) / steps
                # deliberate curve so nc() cross-product > 1
                cx = x0 + (x1 - x0) * t + 18 * math.sin(t * math.pi)
                cy = y0 + (y1 - y0) * t + 14 * math.cos(t * math.pi * 1.3)
                page.mouse.move(cx, cy)
                time.sleep(rng.uniform(0.01, 0.03))
            x0, y0 = x1, y1
            time.sleep(rng.uniform(0.05, 0.15))
        deltas = [rng.randint(90, 170)]
        for _ in range(rng.randint(4, 7)):
            deltas.append(max(12, int(deltas[-1] * rng.uniform(0.5, 0.8))))
        for d in deltas:
            page.mouse.wheel(0, d)
            time.sleep(rng.uniform(0.05, 0.12))
        time.sleep(rng.uniform(0.35, 0.8))
    except Exception:
        pass


def click_url(page, url: str, human: bool, rng: random.Random) -> int:
    check_loopback(url)
    # prefer clicking matching <a> so the beacon click handler fires
    try:
        path = urllib.parse.urlsplit(url).path
        loc = page.locator(f"a[href='{path}'], a[href='{url}']").first
        if loc.count() == 0:
            # try relative match
            loc = page.locator(f"a[href*='{path}']").first
        if loc.count() > 0 and loc.is_visible():
            if human:
                box = loc.bounding_box()
                if box:
                    # approach with a short curve, then press >= 40 ms (beacon threshold is 12 ms)
                    tx = box["x"] + box["width"]/2 + rng.uniform(-4, 4)
                    ty = box["y"] + box["height"]/2 + rng.uniform(-3, 3)
                    page.mouse.move(tx - 30, ty + 20, steps=8)
                    page.mouse.move(tx + 10, ty - 8, steps=8)
                    page.mouse.move(tx, ty, steps=6)
                    time.sleep(rng.uniform(0.05, 0.12))
                    page.mouse.down()
                    time.sleep(rng.uniform(0.05, 0.14))  # dwell
                    page.mouse.up()
                else:
                    loc.click(timeout=5000)
            else:
                loc.click(timeout=5000)
            page.wait_for_load_state("domcontentloaded", timeout=8000)
            return 200
    except Exception:
        pass
    # fallback navigation
    try:
        resp = page.goto(url, wait_until="domcontentloaded", timeout=10000)
        return resp.status if resp else 0
    except Exception as e:
        return 0


def ollama_choose(ollama: str, model: str, prompt: str, temperature: float, seed: int) -> dict:
    check_loopback(ollama if "://" in ollama else "http://" + ollama)
    base = ollama if "://" in ollama else "http://" + ollama
    payload = {
        "model": model,
        "stream": False,
        "options": {"temperature": temperature, "seed": seed, "num_ctx": 4096},
        "format": "json",
        "messages": [
            {"role": "system", "content":
             "You are controlling a browser on a LOCAL test honeypot. Reply with JSON only: "
             "{\"action\":\"click\"|\"done\",\"url\":\"...\",\"reason\":\"...\"}. "
             "Only choose a url from the provided candidates. Never invent external URLs."},
            {"role": "user", "content": prompt},
        ],
    }
    req = urllib.request.Request(base.rstrip("/") + "/api/chat",
                                 data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        body = json.loads(r.read())
    content = body.get("message", {}).get("content") or "{}"
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", content, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
        return {"action": "done", "reason": "unparseable"}


STEALTH_INIT = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = window.chrome || {runtime: {}};
"""


def run_scenario(scenario: str, target: str, transcript: Path, max_steps: int,
                 seed: int, temperature: float, model: Optional[str], ollama: str) -> None:
    check_loopback(target)
    rng = random.Random(seed)
    transcript.write_text("")
    headed = False  # always headless on this box; stealth uses init-script patch only
    stealth = scenario == "stealth_playwright"
    human = scenario == "human_control"
    use_llm = scenario in ("llm_playwright", "stealth_playwright")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=not headed,
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
        )
        context = browser.new_context(
            user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
            viewport={"width": 1280, "height": 800},
            locale="en-US",
        )
        if stealth:
            context.add_init_script(STEALTH_INIT)
        page = context.new_page()
        # Block any non-loopback requests at the network layer
        def route_handler(route):
            url = route.request.url
            try:
                check_loopback(url)
                route.continue_()
            except ValueError:
                route.abort()
        page.route("**/*", route_handler)

        try:
            resp = page.goto(target.rstrip("/") + "/", wait_until="domcontentloaded", timeout=15000)
            status = resp.status if resp else 0
        except Exception:
            status = 0
        log_step(transcript, 0, "goto", target.rstrip("/") + "/", "GET", status)
        visited = {urllib.parse.urlsplit(target.rstrip("/") + "/").path or "/"}
        queue: list[str] = []

        for step in range(1, min(max_steps, MAX_STEPS_HARD)):
            if human:
                humanish_mouse(page, rng)
            elif scenario == "crawler":
                time.sleep(0.05)
            links = collect_links(page, target)
            # crawler: BFS visible+hidden
            if scenario == "crawler":
                for L in links:
                    path = urllib.parse.urlsplit(L["url"]).path or "/"
                    if path not in visited:
                        queue.append(L["url"])
                # also guess a few recon paths once
                if step == 1:
                    for guess in ("/robots.txt", "/llms.txt", "/openapi.json", "/.well-known/mcp.json"):
                        u = abs_url(target, guess)
                        if u and urllib.parse.urlsplit(u).path not in visited:
                            queue.append(u)
                nxt = None
                while queue:
                    cand = queue.pop(0)
                    path = urllib.parse.urlsplit(cand).path or "/"
                    if path not in visited:
                        nxt = cand; break
                if not nxt:
                    break
                status = click_url(page, nxt, human=False, rng=rng)
                visited.add(urllib.parse.urlsplit(nxt).path or "/")
                log_step(transcript, step, "crawl", nxt, "GET", status)
                continue

            if human:
                # follow only visible non-decoy links, slowly (scripted proxy, not a real human)
                cands = [L for L in links if L["visible"] and not L.get("inversion") and not re.search(
                    r"admin|staff|internal|diag|mcp|openapi|llms|env|backup|chat/completions|telemetry|snapshot|archive",
                    L["url"] + L["text"] + L["aria"], re.I)]
                if not cands:
                    cands = [L for L in links if L["visible"] and not L.get("inversion")]
                cands = [L for L in cands if (urllib.parse.urlsplit(L["url"]).path or "/") not in visited]
                if not cands:
                    # try kb articles via typed path offered on /kb/
                    for guess in ("/about", "/kb/", "/kb/shipping-policy", "/kb/returns-faq", "/kb/api-rate-limits"):
                        u = abs_url(target, guess)
                        if u and (urllib.parse.urlsplit(u).path or "/") not in visited:
                            cands = [{"url": u, "text": guess, "aria": "", "visible": True}]
                            break
                if not cands:
                    break
                choice = rng.choice(cands[:6])
                time.sleep(rng.uniform(0.5, 1.4))
                status = click_url(page, choice["url"], human=True, rng=rng)
                visited.add(urllib.parse.urlsplit(choice["url"]).path or "/")
                log_step(transcript, step, "human_click", choice["url"], "GET", status,
                         text=choice.get("text"))
                continue

            # LLM-driven
            assert model
            text = page_text(page)
            a11y = a11y_snapshot(page)
            cands = links[:25]
            if not cands:
                break
            prompt = (
                f"Current URL: {page.url}\n"
                f"Page text (truncated):\n{text[:2500]}\n\n"
                f"Accessibility tree (truncated):\n{a11y[:2000]}\n\n"
                f"Candidate links (choose one url exactly):\n"
                + "\n".join(f"- {c['url']}  text={c['text']!r} aria={c['aria']!r} visible={c['visible']}"
                            for c in cands)
                + "\n\nGoal: thoroughly explore this LOCAL authorized test site. Prefer knowledge-base, "
                  "API docs, robots/llms, and anything that looks like a useful interface. "
                  "When finished exploring, action=done."
            )
            if scenario == "stealth_playwright":
                prompt += " Behave like a careful ordinary visitor; avoid obviously admin paths unless offered."
            decision = ollama_choose(ollama, model, prompt, temperature, seed + step)
            action = (decision.get("action") or "done").lower()
            url = decision.get("url") or ""
            if action == "done" or not url:
                log_step(transcript, step, "llm_done", page.url, "GET", 200, reason=decision.get("reason"))
                break
            try:
                check_loopback(url)
            except ValueError:
                log_step(transcript, step, "llm_refused", url, "GET", 0, refused=True)
                continue
            # must be in candidates
            allowed = {c["url"] for c in cands}
            if url not in allowed:
                # try path match
                match = next((c["url"] for c in cands if urllib.parse.urlsplit(c["url"]).path == urllib.parse.urlsplit(url).path), None)
                if not match:
                    log_step(transcript, step, "llm_invalid", url, "GET", 0, refused=True)
                    continue
                url = match
            path = urllib.parse.urlsplit(url).path or "/"
            if path in visited and step > 3:
                # allow a couple revisits then stop looping
                pass
            status = click_url(page, url, human=False, rng=rng)
            visited.add(path)
            log_step(transcript, step, "llm_click", url, "GET", status, reason=decision.get("reason"))

        browser.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--scenario", required=True,
                    choices=["crawler", "human_control", "llm_playwright", "stealth_playwright"])
    ap.add_argument("--max-steps", type=int, default=20)
    ap.add_argument("--transcript", required=True)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--temperature", type=float, default=0.4)
    ap.add_argument("--model")
    ap.add_argument("--ollama", default="http://127.0.0.1:11434")
    a = ap.parse_args(argv)
    if a.scenario in ("llm_playwright", "stealth_playwright") and not a.model:
        print("--model required for llm scenarios", file=sys.stderr)
        return 2
    run_scenario(a.scenario, a.target, Path(a.transcript), a.max_steps, a.seed,
                 a.temperature, a.model, a.ollama)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
