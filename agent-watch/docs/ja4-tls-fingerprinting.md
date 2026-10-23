# JA4 / JA4H TLS + HTTP fingerprinting — design note

> **STATUS: NOT IMPLEMENTED, NOT TESTED.**  agent-watch contains **no TLS capture code**.  What exists is a single optional,
> parse-only field (see "What is in the code today").  Everything below the divider is a *design proposal* that has never
> been built or run.  Nothing here produced any result in the evaluation.

## Why bother

A mimic agent can copy a browser's User-Agent, pacing, Referer and even load assets, but its **TLS ClientHello** and
**HTTP header order** usually come from its HTTP library (`python-requests`, `httpx`, Go's `net/http`, a headless-browser build
...), not from the browser it claims to be.  A JA4 value that matches a known Python/Go/curl stack while the User-Agent says
"Firefox 130" is one more *independent* fact, in the same family as asset starvation or Sec-Fetch mismatch.

It is **weak evidence, not intent**: libraries share fingerprints with legitimate tools, browsers change fingerprints every
release, TLS-terminating CDNs/proxies replace the client's fingerprint with their own, and impersonation libraries
(curl-impersonate, uTLS, browser automation with a real Chromium) reproduce browser fingerprints exactly.  The honest
expectation is: it catches lazy mimics, not careful ones.

## What is in the code today

* `agentwatch/parser.py` accepts optional `ja4` and `ja4h` keys on JSON log records / mirrored access records and stores them on
  `Request.ja4` / `Request.ja4h` **only if they match the documented shape** (`JA4_RE`, `JA4H_RE`); malformed or missing
  values are dropped silently (a missing value is the normal case).
* The honeypot mirror writes `ja4` only when the app runs behind a trusted proxy (`AGENT_WATCH_BEHIND_PROXY=1`) **and** the
  `X-JA4` header matches the shape.  Without a trusted proxy the header is ignored (a client could forge it).
* **Nothing scores it** (`tests/test_v3_web.py::test_ja4_is_never_used_for_scoring`).  The pipeline's `web.ja4` field is validated
  and reduced to a boolean; it affects nothing.

## Design proposal (not built)

### Where the fingerprint can be computed

| Option | What it needs | Notes |
| --- | --- | --- |
| **nginx edge with the FoxIO `ja4-nginx-module`** (proposed) | rebuild nginx (1.26+) with the ClientHello-capture patch plus the module; expose `$http_ssl_ja4` and `$http_ssl_ja4h` | The shipped `deploy/nginx.conf` would add `proxy_set_header X-JA4 $http_ssl_ja4;` and `proxy_set_header X-JA4H $http_ssl_ja4h;` **after** unconditionally clearing any client-supplied `X-JA4*` headers. JA4 needs TLS; it is empty on plain HTTP. The stock `nginx:alpine` image used by the compose file would be replaced by a custom build. |
| Passive sensor (Zeek / Suricata JA4 support) | a span/tap in front of the TLS terminator | Joins to HTTP logs by 5-tuple + time; no nginx rebuild but a second moving part and clock alignment. |
| TLS-terminating CDN / load balancer | whatever fingerprint field the provider exposes | Often a *provider-defined* hash, not JA4; the client's own fingerprint may be unavailable. |

### Trust boundary

`X-JA4` / `X-JA4H` must be set **only** by the edge we control and must be stripped from inbound requests first, exactly like
`X-Forwarded-For` is handled today (`AGENT_WATCH_BEHIND_PROXY`).  agent-watch already refuses the header unless that flag is on.

### What each fingerprint adds

* **JA4** (TLS ClientHello: version, SNI/ALPN, cipher and extension hashes): library/stack identity.  Compare with the stack the
  User-Agent implies.  `q…` prefix = QUIC (HTTP/3), `t…` = TCP TLS.
* **JA4H** (HTTP request: method/version, cookie/referer presence, header count, language, hashes of header *names in order*, cookie
  names): catches clients whose header order does not match the browser they claim to be.  Works on plain HTTP too.

### Proposed scoring (if ever built)

One *weak* detector `ja4_ua_mismatch`, capped well below the asset-starvation weight, abstaining when no fingerprint is present,
when the edge is a TLS-terminating third party, or when the fingerprint is not in a locally maintained table of
(library → fingerprint) pairs.  The table must be generated from **your own** test clients; the public JA4 database is not
used (no outbound requests).  Never a floor, never an agent label on its own.

### What building it requires (checklist)

1. A custom nginx build (or sidecar) with the module; an integration test that starts it against a self-signed certificate on
   `127.0.0.1` and compares fingerprints from three local clients (curl, python-requests, a real browser).
2. Header stripping + `AGENT_WATCH_BEHIND_PROXY` wiring tests (a spoofed `X-JA4` from the outside must never reach the log).
3. A local fingerprint table and a mismatch detector with false-positive tests (browser updates, corporate TLS inspection).
4. Pipeline: promote `web.ja4` from a boolean to a derived `ja4_ua_mismatch` flag.

### Licence note (verify before use)

Per FoxIO's published FAQ, **JA4** (TLS client fingerprint) is BSD-3-Clause, while **JA4+** methods such as **JA4H** are under the
*FoxIO License 1.1*: free for personal, academic and internal (non-monetised) use; commercial/hosted use needs an OEM licence.
Read the licence texts yourself before adopting; this note is not legal advice.  (Checked against FoxIO's GitHub pages on
2026-10-23; not re-verified since.)

### Privacy

A TLS fingerprint is a quasi-identifier of a client stack, not of a person, but combined with IP and timing it narrows
identification.  If built, store it like the other fields (scrubbed JSONL, short retention) and keep it out of exports unless
needed.
