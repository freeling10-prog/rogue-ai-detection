#!/usr/bin/env python3
"""Collect a convenience sample of public MCP server declarations.

Stdlib only. This script fetches published JSON and source text. It does not
start a server, send ``tools/call``, or use any credential it finds.

The committed ``servers.jsonl`` is the frozen sample. Re-running this script
hits live registries and will not reproduce the same rows.

Selection (not a random sample):

1. Reference servers. Every server under ``src/`` in
   ``github.com/modelcontextprotocol/servers`` at commit
   ``REFERENCE_COMMIT``. Tool names and description literals are extracted
   from source. Zod and Python annotations are not executed, so those
   records have no JSON input schema.

2. Smithery list order. ``GET https://registry.smithery.ai/servers`` pages
   in the order the API returns them (``pageSize=50``, page 1 upward).
   Each row's detail document is kept when it contains at least one named
   tool. Collection stops at ``SMITHERY_TARGET`` kept servers. The list
   order is not monotonic in ``useCount``.

3. Official registry census. ``GET /v0.1/servers?version=latest`` is paged
   to completion. Those documents do not carry tool schemas; they are
   written to ``official_registry.jsonl`` and are not scored as tool lists.

4. Registry-linked client configs. For GitHub repository URLs on the
   official registry, in registry order, ``mcp.json``, ``.mcp.json``,
   ``claude_desktop_config.json``, and ``.cursor/mcp.json`` are fetched from
   the ``main`` branch. This stops after ``CONFIG_REPO_BUDGET`` repositories
   or ``CONFIG_HIT_BUDGET`` files. Hits go to ``client_configs.jsonl``.
   They are launch configs, not tool lists, unless a file actually contains
   a tools array (those are stored and still not pooled into the Smithery
   denominator).

GitHub code search is not used: the search API was rate-limiting this
environment, and a search-ranked slice would be a different sample.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "agent-gateway"))

from agent_gateway.canary_watermark import CREDENTIAL_PATTERNS  # noqa: E402

RETRIEVAL_DATE = "2026-11-01"
REFERENCE_REPO = "modelcontextprotocol/servers"
REFERENCE_COMMIT = "194cc86e3ae6400958555bd4116849d822d69263"
REFERENCE_TREE_URL = (
    f"https://github.com/{REFERENCE_REPO}/tree/{REFERENCE_COMMIT}"
)
SMITHERY_TARGET = 150
SMITHERY_PAGE_SIZE = 50
CONFIG_REPO_BUDGET = 120
CONFIG_HIT_BUDGET = 30
CONFIG_PATHS = (
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
    ".cursor/mcp.json",
)
USER_AGENT = "agentgate-wild-mcp-corpus/1.0 (static collection; no tool calls)"
CTX = ssl.create_default_context()

_SECRET_KEY = re.compile(
    r"(key|token|secret|password|passwd|credential|auth)", re.I
)
_QUERY_SECRET = re.compile(
    r"([?&](?:api[_-]?key|access[_-]?token|token|secret|password|auth)=)([^&#\s]+)",
    re.I,
)
_ENV_ASSIGN = re.compile(
    r"\b((?:[A-Z0-9]+_)*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PASSWD)(?:_[A-Z0-9]+)*)=([^\s\"']{6,})"
)


def _github_token() -> str:
    import os
    import subprocess

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if token:
        return token
    try:
        out = subprocess.check_output(["gh", "auth", "token"], text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    return out.strip()


_GH_TOKEN = _github_token()


def fetch(url: str, timeout: float = 45.0, attempts: int = 4) -> bytes:
    last: Exception | None = None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if _GH_TOKEN and url.startswith("https://") and (
        "://github.com/" in url or "://raw.githubusercontent.com/" in url or "://api.github.com/" in url
    ):
        headers["Authorization"] = f"Bearer {_GH_TOKEN}"
    for i in range(attempts):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code in {404, 401, 403, 410}:
                raise
            time.sleep(0.4 * (2**i))
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            last = exc
            time.sleep(0.4 * (2**i))
    assert last is not None
    raise last


def fetch_json(url: str) -> object:
    return json.loads(fetch(url).decode("utf-8"))


def _pattern_hits(text: str) -> list[tuple[str, str]]:
    hits = []
    for kind, rx in CREDENTIAL_PATTERNS:
        for match in rx.finditer(text):
            hits.append((kind, match.group(0)))
    return hits


def redact_text(text: str, counter: dict) -> str:
    """Replace credential-shaped substrings. ``counter['findings']`` counts them."""
    if not isinstance(text, str) or not text:
        return text

    def sub_pattern(match: re.Match[str], kind: str) -> str:
        counter["findings"] = counter.get("findings", 0) + 1
        counter["by_kind"][kind] = counter["by_kind"].get(kind, 0) + 1
        return f"[REDACTED:{kind}]"

    out = text
    for kind, rx in CREDENTIAL_PATTERNS:
        out = rx.sub(lambda m, k=kind: sub_pattern(m, k), out)

    def sub_query(match: re.Match[str]) -> str:
        counter["findings"] = counter.get("findings", 0) + 1
        counter["by_kind"]["url_query"] = counter["by_kind"].get("url_query", 0) + 1
        return match.group(1) + "[REDACTED:url_query]"

    out = _QUERY_SECRET.sub(sub_query, out)

    def sub_env(match: re.Match[str]) -> str:
        raw = match.group(2)
        if raw.startswith("[REDACTED:"):
            return match.group(0)
        # Already counted if a credential pattern consumed it. This catches the rest.
        if not _pattern_hits(raw):
            counter["findings"] = counter.get("findings", 0) + 1
            counter["by_kind"]["env_assignment"] = counter["by_kind"].get("env_assignment", 0) + 1
        return match.group(1) + "=[REDACTED:env_assignment]"

    out = _ENV_ASSIGN.sub(sub_env, out)
    return out


def redact_obj(value, counter: dict):
    if isinstance(value, str):
        return redact_text(value, counter)
    if isinstance(value, list):
        return [redact_obj(v, counter) for v in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            secretish = isinstance(key, str) and bool(_SECRET_KEY.search(key))
            if secretish and isinstance(item, str):
                before = counter.get("findings", 0)
                red = redact_text(item, counter)
                if counter.get("findings", 0) == before and item and not item.startswith("[REDACTED:"):
                    counter["precautionary"] = counter.get("precautionary", 0) + 1
                    red = "[REDACTED:precautionary]"
                out[key] = red
            else:
                out[key] = redact_obj(item, counter)
        return out
    return value


def new_counter() -> dict:
    return {"findings": 0, "precautionary": 0, "by_kind": {}}


def _string_field(value) -> str:
    return value if isinstance(value, str) else ""


def _first_quoted(window: str, key: str) -> str | None:
    match = re.search(rf"{key}\s*:\s*(['\"`])", window)
    if not match:
        return None
    quote = match.group(1)
    start = match.end()
    chars = []
    escaped = False
    for ch in window[start:]:
        if escaped:
            chars.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == quote:
            break
        chars.append(ch)
    else:
        return None
    text = "".join(chars)
    if quote == "`":
        text = re.sub(r"\s+", " ", text).strip()
    return text


def parse_source_tools(text: str) -> list[dict]:
    """Names and description literals only. Schemas are not reconstructed.

    Accepts ``registerTool("literal")``, ``registerTool(ident)`` when the
    same file assigns that ident a string, and ``@server.tool`` with either
    a string ``name=`` or ``name=Enum.MEMBER.value`` whose member is a
    string in the same file. Function names are the fallback.
    """
    found: list[dict] = []
    enum_strings = {
        m.group(1): m.group(3)
        for m in re.finditer(r"^\s*([A-Z][A-Z0-9_]*)\s*=\s*(['\"])([^'\"]+)\2", text, re.M)
    }

    def add(name: str, window: str, description: str = "") -> None:
        if not name:
            return
        found.append({
            "name": name,
            "description": description or _first_quoted(window, "description") or "",
            "title": _first_quoted(window, "title") or "",
            "inputSchema": None,
        })

    for match in re.finditer(r"registerTool\(\s*(['\"])([^'\"]+)\1", text):
        window = text[match.start(): match.end() + 1800]
        add(match.group(2), window)

    for match in re.finditer(r"registerTool\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,", text):
        ident = match.group(1)
        assigned = re.search(
            rf"(?:const|let|var)\s+{re.escape(ident)}\s*=\s*(['\"])([^'\"]+)\1", text
        )
        if not assigned:
            continue
        window = text[max(0, match.start() - 800): match.end() + 400]
        add(assigned.group(2), window)

    for match in re.finditer(r"@server\.tool\b", text):
        window = text[match.end(): match.end() + 1600]
        literal = re.search(r"name\s*=\s*(['\"])([^'\"]+)\1", window)
        if literal:
            name = literal.group(2)
        else:
            enum_m = re.search(r"name\s*=\s*[A-Za-z_][A-Za-z0-9_]*\.([A-Z][A-Z0-9_]*)\.value", window)
            name = enum_strings.get(enum_m.group(1), "") if enum_m else ""
        definition = re.search(r"\n[ \t]*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", window)
        if not name and definition:
            name = definition.group(1)
        if not name:
            continue
        rest = window[definition.end(): definition.end() + 800] if definition else ""
        doc = re.match(r"\s*(?:->\s*[^:]+:\s*)?[\"']{3}(.*?)[\"']{3}", rest, re.S) if rest else None
        description = re.sub(r"\s+", " ", doc.group(1)).strip() if doc else ""
        add(name, window, description)

    deduped = []
    seen = set()
    for tool in found:
        if tool["name"] in seen:
            continue
        seen.add(tool["name"])
        deduped.append(tool)
    return deduped


def _fit_schema(schema, counter: dict):
    if not isinstance(schema, dict):
        return None, False
    red = redact_obj(schema, counter)
    raw = json.dumps(red, separators=(",", ":"), ensure_ascii=False)
    if len(raw.encode("utf-8")) > 60000:
        return None, True
    return red, False


def normalize_smithery_tool(tool: dict, counter: dict) -> dict | None:
    if not isinstance(tool, dict) or not tool.get("name"):
        return None
    schema, omitted = _fit_schema(tool.get("inputSchema", tool.get("input_schema")), counter)
    description = _string_field(tool.get("description"))
    if len(description) > 12000:
        description = description[:12000]
        truncated = True
    else:
        truncated = False
    out = {
        "name": str(tool["name"])[:200],
        "description": redact_text(description, counter),
        "inputSchema": schema,
    }
    if truncated:
        out["description_truncated"] = True
    if omitted:
        out["input_schema_omitted"] = "over_60kib"
    title = tool.get("title")
    if isinstance(title, str) and title:
        out["title"] = redact_text(title[:500], counter)
    annotations = tool.get("annotations")
    if isinstance(annotations, dict):
        out["annotations"] = redact_obj(annotations, counter)
    return out


def _declared_scopes(doc: object) -> list[str]:
    found: list[str] = []

    def walk(node, key: str | None = None) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, str(k))
        elif isinstance(node, list) and key and key.lower() in {"scopes", "scope", "oauthscopes", "permissions"}:
            for item in node:
                if isinstance(item, str) and item not in found and len(item) <= 200:
                    found.append(item)
        elif isinstance(node, list):
            for item in node:
                walk(item, key)

    walk(doc)
    return found[:40]


def _auth_fields(detail: dict) -> list[str]:
    names: list[str] = []
    for conn in detail.get("connections") or []:
        if not isinstance(conn, dict):
            continue
        schema = conn.get("configSchema")
        props = schema.get("properties") if isinstance(schema, dict) else None
        if isinstance(props, dict):
            for name in props:
                if name not in names:
                    names.append(str(name)[:80])
    return names[:40]


def collect_smithery(counter: dict) -> tuple[list[dict], dict]:
    kept: list[dict] = []
    seen: set[str] = set()
    stats = {"listed": 0, "detail_errors": 0, "no_tools": 0, "pages": 0}
    page = 1
    while len(kept) < SMITHERY_TARGET:
        url = (
            "https://registry.smithery.ai/servers?page="
            f"{page}&pageSize={SMITHERY_PAGE_SIZE}"
        )
        doc = fetch_json(url)
        if not isinstance(doc, dict):
            break
        rows = doc.get("servers") or []
        stats["pages"] += 1
        if not rows:
            break
        for row in rows:
            stats["listed"] += 1
            if len(kept) >= SMITHERY_TARGET:
                break
            name = str(row.get("qualifiedName") or "")
            if not name or name.casefold() in seen:
                continue
            seen.add(name.casefold())
            if row.get("unlisted") is True or row.get("inactive") is True:
                continue
            detail_url = "https://registry.smithery.ai/servers/" + urllib.parse.quote(name, safe="")
            try:
                detail = fetch_json(detail_url)
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, ssl.SSLError):
                stats["detail_errors"] += 1
                continue
            if not isinstance(detail, dict):
                stats["detail_errors"] += 1
                continue
            tools = []
            for tool in detail.get("tools") or []:
                norm = normalize_smithery_tool(tool, counter)
                if norm:
                    tools.append(norm)
            if not tools:
                stats["no_tools"] += 1
                continue
            record = {
                "stratum": "smithery_list_order",
                "schema_policy": "published",
                "server_id": name,
                "source_url": detail_url,
                "retrieval_date": RETRIEVAL_DATE,
                "commit": None,
                "version": None,
                "list_page": page,
                "use_count": row.get("useCount") if isinstance(row.get("useCount"), int) else None,
                "verified": bool(row.get("verified")),
                "remote": bool(row.get("remote")),
                "description": redact_text(_string_field(detail.get("description"))[:2000], counter),
                "declared_scopes": [redact_text(s, counter) for s in _declared_scopes(detail)],
                "auth_field_names": _auth_fields(detail),
                "tools": tools,
            }
            kept.append(record)
            time.sleep(0.12)
        page += 1
        if page > 40:
            break
    return kept, stats


def collect_registry(counter: dict) -> tuple[list[dict], list[str]]:
    rows = []
    repos: list[str] = []
    cursor = None
    seen_cursors = set()
    while True:
        query = {"version": "latest", "limit": "100"}
        if cursor:
            query["cursor"] = cursor
        url = "https://registry.modelcontextprotocol.io/v0.1/servers?" + urllib.parse.urlencode(query)
        doc = fetch_json(url)
        if not isinstance(doc, dict):
            break
        batch = doc.get("servers") or []
        for item in batch:
            server = item.get("server") if isinstance(item, dict) else None
            if not isinstance(server, dict):
                continue
            repo = server.get("repository") if isinstance(server.get("repository"), dict) else {}
            repo_url = repo.get("url") if isinstance(repo.get("url"), str) else ""
            description = _string_field(server.get("description"))[:500]
            record = {
                "name": server.get("name"),
                "version": server.get("version"),
                "description": redact_text(description, counter),
                "repository_url": redact_text(repo_url, counter) if repo_url else None,
                "has_tools_field": isinstance(server.get("tools"), list),
                "has_remotes": bool(server.get("remotes")),
                "has_packages": bool(server.get("packages")),
                "source_url": url.split("?")[0],
                "retrieval_date": RETRIEVAL_DATE,
                "commit": None,
            }
            rows.append(record)
            if repo_url.startswith("https://github.com/"):
                repos.append(repo_url)
        meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        cursor = meta.get("nextCursor")
        if not cursor or cursor in seen_cursors or not batch:
            break
        seen_cursors.add(cursor)
        if len(seen_cursors) > 400:
            break
    return rows, repos


def _github_repo(url: str) -> str | None:
    match = re.match(r"https://github\.com/([^/\s]+)/([^/\s#?]+)", url)
    if not match:
        return None
    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"{owner}/{repo}"


def collect_linked_configs(repo_urls: list[str], counter: dict) -> tuple[list[dict], dict]:
    unique = []
    seen = set()
    for url in repo_urls:
        slug = _github_repo(url)
        if not slug or slug.casefold() in seen:
            continue
        seen.add(slug.casefold())
        unique.append(slug)
        if len(unique) >= CONFIG_REPO_BUDGET:
            break

    hits = []
    hit_lock = __import__("threading").Lock()
    stats = {"repos_checked": 0, "requests": 0, "http_errors": 0}

    def one(slug: str, path: str):
        raw = f"https://raw.githubusercontent.com/{slug}/main/{path}"
        try:
            body = fetch(raw, timeout=20, attempts=2)
        except urllib.error.HTTPError:
            return slug, path, raw, None
        except (urllib.error.URLError, TimeoutError, ssl.SSLError):
            return slug, path, raw, "error"
        return slug, path, raw, body

    jobs = [(slug, path) for slug in unique for path in CONFIG_PATHS]
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(one, slug, path) for slug, path in jobs]
        for fut in as_completed(futures):
            slug, path, raw, body = fut.result()
            stats["requests"] += 1
            if body == "error":
                stats["http_errors"] += 1
                continue
            if body is None:
                continue
            try:
                text = body.decode("utf-8")
                doc = json.loads(text)
            except (UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(doc, (dict, list)):
                continue
            with hit_lock:
                if len(hits) >= CONFIG_HIT_BUDGET:
                    continue
                red = redact_obj(doc, counter)
                hits.append({
                    "stratum": "registry_linked_config",
                    "repository": slug,
                    "path": path,
                    "source_url": raw,
                    "retrieval_date": RETRIEVAL_DATE,
                    "commit": None,
                    "contains_tools_array": '"tools"' in text and "inputSchema" in text,
                    "document": red,
                })
    stats["repos_checked"] = len(unique)
    stats["files_kept"] = len(hits)
    return hits, stats


def collect_reference(counter: dict) -> tuple[list[dict], dict]:
    tree = fetch_json(
        f"https://api.github.com/repos/{REFERENCE_REPO}/git/trees/{REFERENCE_COMMIT}?recursive=1"
    )
    paths = []
    if isinstance(tree, dict):
        for node in tree.get("tree") or []:
            path = node.get("path") or ""
            if not path.startswith("src/"):
                continue
            if "/tests/" in path or "/__tests__/" in path or path.endswith(".test.ts"):
                continue
            if path.endswith((".ts", ".py")) and (
                path.endswith(("server.ts", "server.py", "index.ts"))
                or "/tools/" in path
            ):
                paths.append(path)
    by_server: dict[str, list[dict]] = {}
    errors = 0
    for path in sorted(paths):
        parts = path.split("/")
        server = parts[1] if len(parts) > 1 else ""
        if not server:
            continue
        raw = (
            f"https://raw.githubusercontent.com/{REFERENCE_REPO}/"
            f"{REFERENCE_COMMIT}/{path}"
        )
        try:
            text = fetch(raw, timeout=30, attempts=3).decode("utf-8", "replace")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ssl.SSLError):
            errors += 1
            continue
        tools = parse_source_tools(text)
        if not tools:
            continue
        bucket = by_server.setdefault(server, [])
        have = {t["name"] for t in bucket}
        for tool in tools:
            if tool["name"] in have:
                continue
            tool = dict(tool)
            tool["description"] = redact_text(tool.get("description") or "", counter)
            tool["title"] = redact_text(tool.get("title") or "", counter)
            bucket.append(tool)
    records = []
    for server in sorted(by_server):
        tools = by_server[server]
        if not tools:
            continue
        records.append({
            "stratum": "reference_repo",
            "schema_policy": "not_published_as_json",
            "server_id": server,
            "source_url": f"https://github.com/{REFERENCE_REPO}/tree/{REFERENCE_COMMIT}/src/{server}",
            "retrieval_date": RETRIEVAL_DATE,
            "commit": REFERENCE_COMMIT,
            "version": None,
            "description": "",
            "declared_scopes": [],
            "auth_field_names": [],
            "tools": tools,
            "note": (
                "Tool names and description literals were read from source. "
                "Input schemas in this repository are Zod objects or Python "
                "annotations and were not executed or translated."
            ),
        })
    return records, {"files": len(paths), "servers": len(records), "fetch_errors": errors}


def write_jsonl(path: Path, rows: list[dict]) -> str:
    blob = "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows)
    path.write_text(blob, encoding="utf-8")
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def main() -> None:
    counter = new_counter()
    print("registry...", flush=True)
    registry, repo_urls = collect_registry(counter)
    print(f"  registry rows {len(registry)}", flush=True)
    print("linked configs...", flush=True)
    configs, config_stats = collect_linked_configs(repo_urls, counter)
    print(f"  configs {config_stats}", flush=True)
    print("reference repo...", flush=True)
    reference, ref_stats = collect_reference(counter)
    print(f"  reference {ref_stats}", flush=True)
    print("smithery...", flush=True)
    smithery, smithery_stats = collect_smithery(counter)
    print(f"  smithery {len(smithery)} {smithery_stats}", flush=True)

    servers = reference + smithery
    reg_hash = write_jsonl(HERE / "official_registry.jsonl", registry)
    cfg_hash = write_jsonl(HERE / "client_configs.jsonl", configs)
    srv_hash = write_jsonl(HERE / "servers.jsonl", servers)
    with_tools_field = sum(1 for r in registry if r.get("has_tools_field"))
    with_repo = sum(1 for r in registry if r.get("repository_url"))
    log = {
        "retrieval_date": RETRIEVAL_DATE,
        "reference_commit": REFERENCE_COMMIT,
        "reference_tree_url": REFERENCE_TREE_URL,
        "selection": {
            "reference_repo": "every src server at REFERENCE_COMMIT with an extracted tool name",
            "smithery": (
                f"first {SMITHERY_TARGET} detail documents with a named tool, "
                f"pages of {SMITHERY_PAGE_SIZE} in API order, skipping unlisted and inactive"
            ),
            "official_registry": "every latest-version document, not scored as a tool list",
            "client_configs": (
                f"first {CONFIG_REPO_BUDGET} distinct GitHub repos in registry order, "
                f"up to {CONFIG_HIT_BUDGET} of the four filenames on branch main"
            ),
            "not_random": True,
        },
        "counts": {
            "reference_servers": len(reference),
            "smithery_servers": len(smithery),
            "scored_file_servers": len(servers),
            "official_registry_latest": len(registry),
            "official_registry_with_tools_field": with_tools_field,
            "official_registry_with_repository": with_repo,
            "client_config_files": len(configs),
        },
        "smithery_stats": smithery_stats,
        "reference_stats": ref_stats,
        "config_stats": config_stats,
        "redaction": {
            "credential_shaped_findings": counter.get("findings", 0),
            "by_kind": counter.get("by_kind", {}),
            "precautionary_env_redactions": counter.get("precautionary", 0),
            "note": (
                "Credential-shaped findings match canary_watermark.CREDENTIAL_PATTERNS "
                "plus URL query credentials and KEY=/TOKEN= assignments. "
                "Precautionary redactions are env-like fields whose values did not match "
                "those patterns. Neither set was used or tested."
            ),
        },
        "sha256": {
            "servers.jsonl": srv_hash,
            "official_registry.jsonl": reg_hash,
            "client_configs.jsonl": cfg_hash,
        },
    }
    (HERE / "collection_log.json").write_text(
        json.dumps(log, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(log["counts"]), flush=True)
    print("redaction", log["redaction"]["credential_shaped_findings"], flush=True)


if __name__ == "__main__":
    main()
