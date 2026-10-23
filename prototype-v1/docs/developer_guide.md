# Developer guide

## Event schema
Every collector yields `rogue_detect.schema.Event` objects.
- `ts` (unix seconds), `agent_id`, `kind` (post, message, read, tool_call, access)
- `target`: channel, recipient agent id, url or resource, tool name, or resource path depending on kind
- `text`, `status` (ok or denied), `in_scope`, `ingest_external`, `dest_external`, `payload_bytes`
- `synthetic` (bool) and `source` (provenance label)

Unknown fields are rejected. This is deliberate: it stops extra personal attributes entering the pipeline.

## Write a collector
Subclass `Collector` in `rogue_detect/collectors.py` and implement `collect()` as a generator of validated events. Call `validate_event_dict` on raw input. Complete the checklist in `ethics_and_compliance.md` before using any real source.

## Add a detector
- Per-agent detectors take the feature matrix from `extract_features` and return a score or flag. See `IsolationForestDetector`.
- Rule detectors live in `run_rules` and should key on technical gates (denied or out-of-scope requests) rather than inferred intent.
- Pair detectors extend `CoordinationDetector`. Each new signal should be independent of the existing ones, because clusters require two independent evidence types.
- Wire the detector into `pipeline.analyze`, give each alert an explanation, and tag it with MITRE ATLAS technique ids from `alerts.ATLAS` (verify ids against the current ATLAS data file).

## Test
`python -m pytest -q` from the project root. Add a hand-built case and a benign look-alike for every new detector.

## Evaluate
`rogue_detect.evaluate.evaluate` compares alerts to the generator's roles. The roles are planted by the same author as the detectors, so treat results as a regression check, not as accuracy evidence. The stealth variant (`python run.py demo`) shows the evasions the current detectors miss.

## Share
`python run.py export-stix` writes a STIX 2.1 bundle of medium and high alerts, labeled synthetic. Real sharing needs human review first (see `responsible_disclosure.md`).
