# Zone A nginx / gunicorn smoke test

Docker is not installed on this machine (`docker` is not on `PATH`, and `docker info` failed). The compose stack in `agent-watch/deploy/docker-compose.zone-a.yml` was not built or started. Container egress was not tested. The file still declares the honeypot network as `internal: true` (no egress); `tests/test_zone_a.py` checks that declaration, which is not a runtime proof.

What ran instead, on 23 Oct 2026 at 3:59 AM Pacific (America/Los_Angeles), all on 127.0.0.1:

- `nginx -t -c agent-watch/deploy/nginx.conf` with nginx 1.24.0 (Ubuntu). The compose upstream name `agentwatch` was added to `/etc/hosts` only for this check, then removed. Result: **syntax is ok, test is successful**.
- Gunicorn from `deploy/gunicorn.conf.py` (`--workers 2 --threads 4`), bound to `127.0.0.1` with `AGENT_WATCH_ALLOW_NONLOCAL` unset. It started and answered `/robots.txt`.
- A loopback nginx in front of that gunicorn, using the shipped config with only paths, the listen address, and the upstream port rewritten so nothing bound a public interface. Ten HTTP requests went to nginx (`Server: nginx`). Nothing was sent directly to gunicorn.

## What the access log showed

`python -m agentwatch analyze` on the nginx JSON log: **10 requests, 0 parse errors**.

| Check | Result |
|---|---|
| Client IP | Every line has `"client_ip":"127.0.0.1"`, including a request that sent `X-Forwarded-For: 203.0.113.50` and `X-Real-IP: 198.51.100.8`. The parser kept `127.0.0.1`. Lead records written by the app also have `source_ip` `127.0.0.1` only. |
| Millisecond timestamps | Raw stamps look like `2026-10-23T10:59:45.718+00:00`. The parser kept the fraction (`microsecond` 718000, 723000, …). Two lines share `.746`; millisecond precision does not make stamps unique. |
| 20 KB body | `POST` of 20480 bytes returned **413**. The body is nginx's HTML error page, and the error log says `client intended to send too large body: 20480 bytes`. The JSON log records `"status":413`. |

## Fixes in `deploy/nginx.conf`

`$time_iso8601` on nginx 1.24.0 is whole seconds (`2026-10-23T10:55:10+00:00`). The log now uses `$aw_timestamp`, which keeps an existing fraction or inserts the `$msec` fraction in front of the timezone. A later nginx that already puts milliseconds in `$time_iso8601` is left as-is.

`error_log /dev/stderr` made `nginx -t` fail here (`open() "/dev/stderr" failed`, because stderr is a socket). It is now `error_log stderr warn;`, which still sends errors to stderr and not to the log volume, and `nginx -t` succeeds.

`X-Forwarded-For` was already overwritten with `$remote_addr` (not `$proxy_add_x_forwarded_for`). The spoofed header did not become the logged client, so that header block was left as written.
