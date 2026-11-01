#!/usr/bin/env python3
"""Uniform sample of Smithery servers that publish a tool schema.

Python 3.12 standard library, plus the collector's redaction helpers. This
script reads the public registry list and detail documents. It does not open
a deployment URL or invoke a tool.

The list endpoint's default pagination stops at 500 rows (``totalPages`` is
10 at ``pageSize=50`` and 5 at ``pageSize=100``) even when ``totalCount`` is
about 20,000. Passing the documented ``seed`` query parameter unlocks the
remaining pages. On 2026-11-01 that parameter did not reshuffle the rows:
several distinct seeds returned the same page. The unlocked order is still
roughly monotone in ``useCount``. The uniform draw is therefore not the API
seed. It is a Fisher-Yates shuffle of the retrieved eligible names, from
``random.Random`` in CPython 3.12.

Population. The sampling frame is every distinct qualified name returned by
that seeded enumeration, minus rows marked unlisted or inactive and minus
empty or duplicate names. The study population is the subset of the frame
that publishes at least one named tool whose ``inputSchema`` is a JSON
object. Servers outside Smithery, and Smithery servers with no published
object schema, are not in the population. The official MCP registry was
already counted in the v1 census (0 of 40,100 latest documents had a tools
array) and is not pooled in here.

Draw. ``random.Random(SAMPLE_SEED).shuffle`` permutes the frame. Details are
read in that order. The first ``TARGET_N`` servers with a published object
schema are the sample. In a uniform random permutation, the relative order
of the schema-publishing subset is itself uniform, so those first ``TARGET_N``
successes are a simple random sample of that subset. A fetch batch may
request past the stopping index; responses after the ``TARGET_N``-th success
are discarded and are not part of the sample.
"""
from __future__ import annotations

import hashlib
import json
import random
import sys
import time
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.wild_mcp_corpus.collect import (  # noqa: E402
    _auth_fields,
    _declared_scopes,
    _string_field,
    fetch_json,
    new_counter,
    normalize_smithery_tool,
    redact_text,
)

# Smithery's `seed` unlocks pages past the 500-row cap. It is not the shuffle seed.
ENUM_SEED = 20261101
# CPython 3.12 random.Random.shuffle of the eligible frame.
SAMPLE_SEED = 20261101
PAGE_SIZE = 100
TARGET_N = 250
MAX_EXAMINED = 5000
LIST_URL = "https://registry.smithery.ai/servers"
DETAIL_URL = "https://registry.smithery.ai/servers/"
DOCS_URL = "https://smithery.ai/docs/api-reference/servers/list-all-servers"
STRATUM = "smithery_uniform"
# Responses fetched past the stopping index are discarded. The batch size is
# only a transport detail.
DETAIL_BATCH = 12
PAGE_WORKERS = 6
DETAIL_WORKERS = 8


def eligible_frame(rows: list[dict]) -> tuple[list[dict], dict]:
    """Eligible list rows in first-seen order, plus exclusion counts.

    ``rows`` are list-API objects, already in retrieval order. A row is
    excluded when its qualified name is missing, when that name was already
    kept (case-folded), or when the row is marked unlisted or inactive.
    Unlisted and inactive are the same exclusions as the v1 convenience sample.
    """
    kept: list[dict] = []
    seen: set[str] = set()
    stats = {
        "rows": len(rows),
        "missing_name": 0,
        "duplicate": 0,
        "unlisted": 0,
        "inactive": 0,
        "eligible": 0,
    }
    for row in rows:
        if not isinstance(row, dict):
            stats["missing_name"] += 1
            continue
        name = str(row.get("qualifiedName") or "").strip()
        if not name:
            stats["missing_name"] += 1
            continue
        if row.get("unlisted") is True:
            stats["unlisted"] += 1
            continue
        if row.get("inactive") is True:
            stats["inactive"] += 1
            continue
        key = name.casefold()
        if key in seen:
            stats["duplicate"] += 1
            continue
        seen.add(key)
        homepage = row.get("homepage") if isinstance(row.get("homepage"), str) else ""
        kept.append({
            "qualified_name": name,
            "use_count": row.get("useCount") if isinstance(row.get("useCount"), int) else None,
            "verified": bool(row.get("verified")),
            "remote": bool(row.get("remote")),
            "unlisted": False,
            "inactive": False,
            "created_at": row.get("createdAt") if isinstance(row.get("createdAt"), str) else None,
            "homepage": homepage[:500],
            "list_page": row.get("_list_page"),
            "list_position": row.get("_list_position"),
        })
    stats["eligible"] = len(kept)
    return kept, stats


def permutation(n: int, seed: int) -> list[int]:
    """Fisher-Yates order of ``range(n)`` from ``random.Random(seed).shuffle``.

    CPython 3.12. The same seed and the same ``n`` reproduce the same list.
    """
    if n < 0:
        raise ValueError("n must be >= 0")
    order = list(range(n))
    random.Random(seed).shuffle(order)
    return order


def frame_sha256(frame: list[dict]) -> str:
    blob = "\n".join(row["qualified_name"] for row in frame).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def classify_detail(detail: object, counter: dict) -> tuple[str, list[dict], dict]:
    """Decide whether a detail document enters the schema-publishing population.

    Tools whose ``inputSchema`` is not a JSON object are dropped and are not
    scored. A missing schema is not treated as an open channel. A server with
    no remaining tool is not in the population.
    """
    meta = {"tools_seen": 0, "tools_dropped_no_schema": 0, "tools_oversize": 0}
    if not isinstance(detail, dict):
        return "detail_not_object", [], meta
    raw_tools = detail.get("tools")
    if not isinstance(raw_tools, list) or not raw_tools:
        return "no_named_tool", [], meta
    kept: list[dict] = []
    named = 0
    for tool in raw_tools:
        if not isinstance(tool, dict) or not tool.get("name"):
            continue
        named += 1
        schema = tool.get("inputSchema", tool.get("input_schema"))
        if not isinstance(schema, dict):
            meta["tools_dropped_no_schema"] += 1
            continue
        norm = normalize_smithery_tool(tool, counter)
        if norm is None:
            meta["tools_dropped_no_schema"] += 1
            continue
        if norm.get("input_schema_omitted") == "over_60kib" or not isinstance(norm.get("inputSchema"), dict):
            meta["tools_oversize"] += 1
            meta["tools_dropped_no_schema"] += 1
            continue
        kept.append(norm)
    meta["tools_seen"] = named
    if named == 0:
        return "no_named_tool", [], meta
    if not kept:
        if meta["tools_oversize"] and meta["tools_oversize"] == named:
            return "schema_oversize", [], meta
        return "no_object_schema", [], meta
    return "kept", kept, meta


def walk_permutation(
    n: int,
    seed: int,
    outcome_of: dict[int, str] | None = None,
    classify=None,
    target: int = TARGET_N,
) -> list[dict]:
    """Walk the seeded permutation until ``target`` ``kept`` outcomes.

    Tests pass ``outcome_of`` (frame index to outcome). The collector passes
    ``classify(frame_index) -> outcome``. Exactly one of the two is set.
    Returns one decision dict per examined index, in permutation order, and
    stops at the target-th ``kept`` so later batch responses never enter.
    """
    if target < 0:
        raise ValueError("target must be >= 0")
    if (outcome_of is None) == (classify is None):
        raise ValueError("pass exactly one of outcome_of or classify")
    decisions = []
    kept = 0
    for draw_position, frame_index in enumerate(permutation(n, seed)):
        if outcome_of is not None:
            outcome = outcome_of[frame_index]
        else:
            outcome = classify(frame_index)
        decisions.append({
            "draw_position": draw_position,
            "frame_index": frame_index,
            "outcome": outcome,
        })
        if outcome == "kept":
            kept += 1
            if kept >= target:
                break
    return decisions


def _use_adjacent_nonincreasing(values: list[int]) -> dict | None:
    """How monotone the API order is. Descriptive, not a sampling weight."""
    if len(values) < 2:
        return None
    pairs = len(values) - 1
    nonincreasing = sum(1 for a, b in zip(values, values[1:]) if a >= b)
    return {"adjacent_pairs": pairs, "nonincreasing": nonincreasing,
            "share": f"{nonincreasing / pairs:.6f}"}


def build_record(frame_row: dict, detail: dict, tools: list[dict], counter: dict,
                 retrieval_date: str, meta: dict, frame_index: int, draw_position: int) -> dict:
    name = frame_row["qualified_name"]
    homepage = redact_text(frame_row.get("homepage") or "", counter)
    return {
        "stratum": STRATUM,
        "schema_policy": "published",
        "server_id": name,
        "source_url": DETAIL_URL + urllib.parse.quote(name, safe=""),
        "retrieval_date": retrieval_date,
        "commit": None,
        "version": None,
        "list_page": frame_row.get("list_page"),
        "frame_index": frame_index,
        "draw_position": draw_position,
        "use_count": frame_row.get("use_count"),
        "verified": frame_row.get("verified"),
        "remote": frame_row.get("remote"),
        "homepage": homepage or None,
        "description": redact_text(_string_field(detail.get("description"))[:2000], counter),
        "declared_scopes": [redact_text(s, counter) for s in _declared_scopes(detail)],
        "auth_field_names": _auth_fields(detail),
        "tools_dropped_no_schema": meta.get("tools_dropped_no_schema", 0),
        "tools": tools,
    }


def _list_url(page: int) -> str:
    query = urllib.parse.urlencode({
        "page": page,
        "pageSize": PAGE_SIZE,
        "seed": ENUM_SEED,
    })
    return f"{LIST_URL}?{query}"


def fetch_list_page(page: int) -> dict:
    doc = fetch_json(_list_url(page))
    if not isinstance(doc, dict):
        raise ValueError(f"list page {page} was not an object")
    return doc


def enumerate_frame(fetch_page=fetch_list_page, workers: int = PAGE_WORKERS) -> tuple[list[dict], dict]:
    """Every list row the seeded endpoint returns, in page order."""
    first = fetch_page(1)
    pagination = first.get("pagination") if isinstance(first.get("pagination"), dict) else {}
    total_pages = int(pagination.get("totalPages") or 1)
    total_count = pagination.get("totalCount")
    page_size = pagination.get("pageSize")
    docs = {1: first}
    if total_pages > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(fetch_page, page): page for page in range(2, total_pages + 1)}
            for fut in futures:
                page = futures[fut]
                docs[page] = fut.result()
    rows: list[dict] = []
    position = 0
    page_counts = []
    for page in range(1, total_pages + 1):
        batch = docs[page].get("servers") if isinstance(docs[page], dict) else None
        if not isinstance(batch, list):
            batch = []
        page_counts.append(len(batch))
        for row in batch:
            if isinstance(row, dict):
                row = dict(row)
                row["_list_page"] = page
                row["_list_position"] = position
            rows.append(row)
            position += 1
    meta = {
        "list_url": LIST_URL,
        "docs_url": DOCS_URL,
        "enum_seed": ENUM_SEED,
        "page_size_requested": PAGE_SIZE,
        "page_size_reported": page_size,
        "total_pages": total_pages,
        "total_count_reported": total_count,
        "rows_retrieved": len(rows),
        "page_row_counts_head": page_counts[:3],
        "page_row_counts_tail": page_counts[-3:],
    }
    return rows, meta


def _detail_one(name: str) -> tuple[str, object, str | None]:
    url = DETAIL_URL + urllib.parse.quote(name, safe="")
    try:
        return name, fetch_json(url), None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return name, None, type(exc).__name__


def draw_sample(frame: list[dict], retrieval_date: str, target: int = TARGET_N) -> tuple[list[dict], dict, dict]:
    """Fetch details in permutation order and keep the first ``target`` schemas."""
    counter = new_counter()
    order = permutation(len(frame), SAMPLE_SEED)
    kept: list[dict] = []
    decisions: list[dict] = []
    outcome_counts: dict[str, int] = {}
    cursor = 0
    while cursor < len(order) and len(kept) < target and len(decisions) < MAX_EXAMINED:
        batch = order[cursor: cursor + DETAIL_BATCH]
        names = [frame[i]["qualified_name"] for i in batch]
        fetched: dict[str, tuple[object, str | None]] = {}
        with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
            for name, detail, err in pool.map(_detail_one, names):
                fetched[name] = (detail, err)
        for offset, frame_index in enumerate(batch):
            if len(kept) >= target or len(decisions) >= MAX_EXAMINED:
                break
            row = frame[frame_index]
            detail, err = fetched[row["qualified_name"]]
            draw_position = cursor + offset
            if err is not None or detail is None:
                outcome = "detail_error"
                meta = {"error": err or "empty"}
                tools: list[dict] = []
            else:
                outcome, tools, meta = classify_detail(detail, counter)
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
            decisions.append({
                "draw_position": draw_position,
                "frame_index": frame_index,
                "outcome": outcome,
            })
            if outcome == "kept" and isinstance(detail, dict):
                kept.append(build_record(
                    row, detail, tools, counter, retrieval_date, meta, frame_index, draw_position,
                ))
        cursor += len(batch)
        print(f"  examined {len(decisions)} kept {len(kept)}", flush=True)
        time.sleep(0.05)
    log = {
        "sample_seed": SAMPLE_SEED,
        "rng": "CPython 3.12 random.Random.shuffle (Fisher-Yates)",
        "target_n": target,
        "examined": len(decisions),
        "kept": len(kept),
        "outcomes": dict(sorted(outcome_counts.items())),
        "stopped_early": len(kept) < target,
        "discarded_note": (
            "Detail fetches past the target-th success in a batch are not recorded "
            "and are not in the sample."
        ),
        "redaction": {
            "credential_shaped_findings": counter.get("findings", 0),
            "by_kind": counter.get("by_kind", {}),
            "precautionary_env_redactions": counter.get("precautionary", 0),
        },
    }
    return kept, decisions, log


def write_jsonl(path: Path, rows: list[dict]) -> str:
    blob = "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows)
    path.write_text(blob, encoding="utf-8")
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def decisions_follow_permutation(
    n: int, seed: int, decisions: list[dict], target: int, max_examined: int | None = None,
) -> bool:
    """The recorded walk is a prefix of the seeded permutation.

    It stops on the ``target``-th ``kept`` outcome, or at the end of the frame,
    or at ``max_examined`` when the schema-publishing subset is smaller than
    the target inside that prefix.
    """
    expected = permutation(n, seed)
    if not decisions:
        return target == 0
    if [d["frame_index"] for d in decisions] != expected[: len(decisions)]:
        return False
    if [d["draw_position"] for d in decisions] != list(range(len(decisions))):
        return False
    kept = sum(1 for d in decisions if d["outcome"] == "kept")
    if kept > target:
        return False
    if kept == target:
        return decisions[-1]["outcome"] == "kept"
    if len(decisions) == n:
        return True
    return max_examined is not None and len(decisions) == max_examined


def main() -> None:
    from datetime import datetime, timezone

    started = datetime.now(timezone.utc)
    retrieval_date = started.date().isoformat()
    print("enumerating Smithery list...", flush=True)
    rows, list_meta = enumerate_frame()
    print(f"  retrieved {list_meta['rows_retrieved']} reported {list_meta['total_count_reported']}", flush=True)
    frame, frame_stats = eligible_frame(rows)
    homepage_counter = new_counter()
    for row in frame:
        row["homepage"] = redact_text(row.get("homepage") or "", homepage_counter)[:500]
    use_values = [r["use_count"] for r in frame if isinstance(r.get("use_count"), int)]
    digest = frame_sha256(frame)
    frame_hash = write_jsonl(HERE / "smithery_frame.jsonl", frame)
    print(f"  eligible {frame_stats['eligible']} sha256 {digest}", flush=True)
    print("drawing sample...", flush=True)
    kept, decisions, draw_log = draw_sample(frame, retrieval_date, TARGET_N)
    if not decisions_follow_permutation(len(frame), SAMPLE_SEED, decisions, TARGET_N, MAX_EXAMINED):
        raise SystemExit("draw decisions do not follow the seeded permutation")
    sample_hash = write_jsonl(HERE / "random_servers.jsonl", kept)
    finished = datetime.now(timezone.utc)
    log = {
        "retrieval_date": retrieval_date,
        "retrieved_at_utc": started.isoformat(),
        "finished_at_utc": finished.isoformat(),
        "stratum": STRATUM,
        "population": (
            "Simple random sample of Smithery-listed servers that published at least one "
            "named tool with a JSON object inputSchema on the retrieval date, after excluding "
            "unlisted rows, inactive rows, empty names, and case-folded duplicate names. "
            "Not a sample of all public MCP servers, and not a sample of Smithery servers "
            "that published no tool schema."
        ),
        "list": list_meta,
        "frame": frame_stats,
        "frame_homepage_redaction": {
            "credential_shaped_findings": homepage_counter.get("findings", 0),
            "by_kind": homepage_counter.get("by_kind", {}),
            "precautionary_env_redactions": homepage_counter.get("precautionary", 0),
        },
        "frame_sha256_names": digest,
        "frame_file_sha256": frame_hash,
        "api_order_use_count": _use_adjacent_nonincreasing(use_values),
        "draw": draw_log,
        "decisions": decisions,
        "sha256": {"random_servers.jsonl": sample_hash, "smithery_frame.jsonl": frame_hash},
        "no_mcp_connection": (
            "Only registry.smithery.ai list and detail documents were fetched. "
            "deploymentUrl was not requested and was not stored."
        ),
    }
    (HERE / "random_collection_log.json").write_text(
        json.dumps(log, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"kept": len(kept), "examined": draw_log["examined"], "frame": frame_stats["eligible"]}))


if __name__ == "__main__":
    main()
