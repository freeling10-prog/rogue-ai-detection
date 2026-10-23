# Tier 3 - wild honeypot traffic

**STATUS: EMPTY. No wild data yet.** `slot/` holds only a `.gitkeep`; the bundle's `DATASET_CARD.md` says so.

Put pulled logs in `slot/`: `provenance.json` (schema `schema/provenance.schema.json`), `*.access.jsonl` (agentwatch.access/1 or an
nginx JSON log with timestamp/ip/method/path/status fields), `*.leads.jsonl` (agentwatch.lead/1), optional `*.report.json`
(agentwatch.report/1). The honeypot must have run on an isolated edge host with no credentials or private network access.

The packer scans every file in all views (raw, `%40`-style percent encoding, `\uXXXX`, newline-split) for API keys, GitHub tokens, AWS
keys, JWTs, Bearer tokens, emails and the honeypot's fake-credential tokens and **refuses to package** if anything is found. Scrub at the
source, or pass `--scrub-inputs` to scrub with the project scrubber and re-verify. IP addresses are not treated as secrets: review before sharing.

`harness_archetype` (on log records or report sessions) is read when present; otherwise clients are counted as `unlabelled`.
