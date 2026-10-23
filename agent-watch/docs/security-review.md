# Honeypot security review

Reviewed `agent-watch/agentwatch/honeypot.py`, `coordination.py`, `wsgi.py`, `scrubber.py`, and `state.py`, plus the request path they share (`honeytoken.py` capture and `leads.py` writes). No outbound network calls were added. Fixes are covered by tests in `tests/test_scrubber.py` and `tests/test_zone_a.py`.

## Fixed

**Secrets split or encoded still reached the lead log.** The scrubber deletes most control characters before matching, but it kept CR, LF, and TAB, and `sanitize_text` turns those into the two-character escapes `\n`, `\r`, and `\t` *before* scrubbing. A token broken by a newline no longer matched. The same gap existed for percent-encoding (`%40`, `%20`, a second encoding round such as `%2540`) and for a JSON `\uXXXX` escape. The matcher now decodes those forms and treats the gap characters as invisible while matching, then redacts the original span. A newline that is not inside a secret is still stored as `\n`, so it cannot add a forged log line.

**SQLite column names were checked with `assert`.** `python -O` strips asserts, and `update` / `consume_nonce` interpolate the column name. Unexpected names now raise `ValueError`. `hit_kinds([])` used to build `IN ()`, which is invalid SQL; an empty key list returns an empty set.

## Checked and not changed

**Code execution.** These modules do not `eval`, `exec`, or start a process on visitor input. HTML is passed through `escape`. Coordination responses are fixed JSON; submitted text is stored, not reflected. Canary ids and article slugs are either server-generated or looked up in a fixed table.

**Path traversal.** `/kb/<slug>`, `/canary/<cid>`, and the `<path:rest>` admin/export routes do not open files. `rest` is ignored. Registry, salt, and sqlite paths come from the environment, not the request.

**SSRF.** None of these modules open a socket or fetch a URL. The canary text tells a client to GET a relative `/canary/<id>` path; the server does not follow it.

**Unbounded memory or disk.** Request bodies are capped at 16 KiB (413 above that) and at most 4 KiB is logged. The lead file stops at its byte cap. The board store evicts sessions past `max_sessions` (default 2000), hit rows past 20 000, and reject rows past 5 000. In-process timing state is capped at 5 000 keys. The tarpit caps delay and concurrency. Coordination fields are clipped (2048 characters, 50 tools).

**Log injection.** CR/LF/TAB in logged text become visible escapes, and the lead writer uses `json.dumps(..., ensure_ascii=True)`, so one record stays one line. Existing tests cover a query and body that contain CR/LF and an ANSI escape.

**Unscrubbed visitor text in sqlite.** The state file stores server-issued board tokens, nonce hashes, session ids, and client IPs. It does not store prompt text or bodies. IPs are there so a later request can be marked cross-IP; that is intentional.

**Proxy headers.** `wsgi.py` never turns on the test-only `trust_forwarded_for` hook. `AGENT_WATCH_BEHIND_PROXY=1` trusts one hop via Werkzeug `ProxyFix`. The shipped nginx sets `X-Forwarded-For` to `$remote_addr` and clears `X-Real-IP`. A loopback check with a forged `X-Forwarded-For` still logged `127.0.0.1` (see `docs/docker-smoke-test.md`).

## Residual

- Redaction is a list of shapes (key prefixes, JWT, bearer, email). A secret that matches none of them is stored.
- nginx's own `error_log` can still quote a request line on a protocol error. It goes to stderr, not the JSON access log.
- The Zone A image sets `AGENT_WATCH_BEHIND_PROXY=1`. That is safe behind the shipped nginx. Publishing the gunicorn port directly would let a client supply the one trusted hop. The compose file does not publish that port.
- Runtime proof that the honeypot container has no route to the internet was not collected: Docker is not available here. The compose file's `internal: true` network is what the unit test checks.
