"""Vendor-risk proof generator: deterministic output, HTML escaping, tamper detection.

Plain ``unittest``; also collected by pytest. Every key is passed in, so the
suite does not depend on ``AGENT_GATEWAY_HMAC_KEY``.
"""
from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

from agent_gateway import capability_token, vendor_risk_proof as V
from agent_gateway.audit_chain import GENESIS, canonical, link, verify_chain_lines
from agent_gateway.sarif_export import validate_sarif
from agent_gateway.schema_integrity_guard import manifest_mac, schema_digest

KEY = b"unit-test-key-for-vendor-risk-proof!"
OTHER_KEY = b"another-key-entirely-for-the-tests!!"
WHEN = "2026-11-13T09:30:00Z"


def _tool(name, description="d", properties=None, **extra):
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties or {"q": {"type": "string"}}}, **extra}


def _config(**extra):
    return {
        "vendor": {"name": "Acme Test Co", "product": "Agent"},
        "review": {"id": "R-1", "period_start": "2026-10-01", "period_end": "2026-10-31"},
        "servers": {
            "research": {"url": "https://research.example/mcp", "tools": [_tool("fetch_url", properties={"url": {"type": "string"}})]},
            "data": {"tools": [_tool("get_customer"), _tool("read_api_credentials")]},
            "mail": {"tools": [_tool("send_email", properties={"body": {"type": "string"}})]},
        },
        **extra,
    }


def _chain(records):
    lines, prev = [], GENESIS
    for seq, record in enumerate(records):
        entry = link({"ts": 1000 + seq, **record}, seq, prev)
        prev = entry["entry_hash"]
        lines.append(json.dumps(entry, sort_keys=True))
    return lines


LOG = [
    {"kind": "CAP_ATTACH", "session_id": "s", "tid": "ab" * 8, "scope": "session", "caveats": 2},
    {"kind": "P3_COMMIT", "cid": "s", "charge_qb": 60, "spent_qb": 60, "overdraft_qb": 0},
    {"kind": "P3_COMMIT", "cid": "s", "charge_qb": 60, "spent_qb": 120, "overdraft_qb": 0},
    {"kind": "LEAKAGE_BUDGET_HOLD", "cid": "s", "charge_qb": 60, "spent_qb": 120, "budget_qb": 128},
    {"kind": "CAPABILITY_TOKEN_DENIED", "session_id": "s", "tool": "send_email", "reason": "CAP_TOOL"},
    {"kind": "ssrf_boundary_violation", "session_id": "s", "tool": "fetch_url"},
]


def _gen(config=None, **kwargs):
    kwargs.setdefault("key", KEY)
    kwargs.setdefault("generated_at", WHEN)
    return V.VendorRiskProofGenerator(_config() if config is None else config, **kwargs)


def _pins(config):
    return {name: {t["name"]: {"schema_sha256": schema_digest(t), "descriptor_sha256": V.descriptor_digest(t)}
                   for t in server["tools"]} for name, server in config["servers"].items()}


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.attrs, self.text = [], [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend(attrs)

    def handle_data(self, data):
        self.text.append(data)


def _parse(page):
    parser = _Tags()
    parser.feed(page)
    parser.close()
    return parser


class DeterminismTests(unittest.TestCase):
    def test_same_inputs_give_the_same_bytes(self):
        lines = _chain(LOG)
        one, two = _gen(audit_log=lines), _gen(audit_log=list(lines))
        self.assertEqual(one.to_json(), two.to_json())
        self.assertEqual(one.to_html(), two.to_html())
        self.assertEqual(one.to_json(), one.to_json())

    def test_listing_order_does_not_change_the_output(self):
        config = _config()
        shuffled = copy.deepcopy(config)
        shuffled["servers"] = dict(reversed(list(shuffled["servers"].items())))
        shuffled["servers"]["data"]["tools"].reverse()
        a, b = _gen(config).build(), _gen(shuffled).build()
        self.assertEqual(a["body"]["schema_pins"], b["body"]["schema_pins"])
        self.assertEqual(a["body"]["exposure"], b["body"]["exposure"])
        self.assertEqual(a["sarif"], b["sarif"])
        # The configuration digest is over the document as given, so it does differ.
        self.assertNotEqual(a["body"]["inputs"]["config_sha256"], b["body"]["inputs"]["config_sha256"])

    def test_time_and_key_change_the_signature_and_nothing_else_in_the_facts(self):
        base = _gen().build()
        later = _gen(generated_at="2026-12-01T00:00:00Z").build()
        rekeyed = _gen(key=OTHER_KEY).build()
        self.assertNotEqual(base["attestation"]["signature"], later["attestation"]["signature"])
        self.assertNotEqual(base["attestation"]["signature"], rekeyed["attestation"]["signature"])
        self.assertNotEqual(base["attestation"]["key_id"], rekeyed["attestation"]["key_id"])
        self.assertEqual(base["attestation"]["body_sha256"], rekeyed["attestation"]["body_sha256"])
        self.assertEqual(base["body"]["schema_pins"], later["body"]["schema_pins"])

    def test_timestamps_are_normalised_and_bad_ones_refused(self):
        self.assertEqual(V.parse_timestamp("2026-11-13T10:30:00+01:00"), WHEN)
        self.assertEqual(V.parse_timestamp("2026-11-13T09:30:00"), WHEN)
        for bad in ("", "yesterday", None, 5):
            with self.assertRaises(V.ProofInputError):
                V.parse_timestamp(bad)

    def test_digests_are_the_gateway_pin_and_plain_sha256(self):
        doc = _gen().build()
        config = _config()
        by_name = {(r["server"], r["tool"]): r for r in doc["body"]["schema_pins"]["tools"]}
        for server, cfg in config["servers"].items():
            for tool in cfg["tools"]:
                row = by_name[(server, tool["name"])]
                self.assertEqual(row["schema_sha256"], schema_digest(tool))
                pinned = {"name": tool["name"], "description": tool["description"], "inputSchema": tool["inputSchema"]}
                self.assertEqual(row["schema_sha256"], hashlib.sha256(canonical(pinned)).hexdigest())
                self.assertRegex(row["descriptor_sha256"], r"^[0-9a-f]{64}$")
        att = doc["attestation"]
        self.assertEqual(att["body_sha256"], hashlib.sha256(canonical(doc["body"])).hexdigest())
        self.assertEqual(att["sarif_sha256"], hashlib.sha256(canonical(doc["sarif"])).hexdigest())

    def test_the_demo_is_byte_stable(self):
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            V.write_demo(Path(one))
            V.write_demo(Path(two))
            for name in (V.DEMO_ATTESTATION_NAME, V.DEMO_REPORT_NAME):
                self.assertEqual((Path(one) / name).read_bytes(), (Path(two) / name).read_bytes())


    def test_the_committed_sample_is_what_the_generator_writes(self):
        docs = Path(V.__file__).resolve().parents[1] / "docs"
        if not (docs / V.DEMO_ATTESTATION_NAME).is_file():
            self.skipTest("sample packet not present in this checkout")
        with tempfile.TemporaryDirectory() as tmp:
            V.write_demo(Path(tmp))
            for name in (V.DEMO_ATTESTATION_NAME, V.DEMO_REPORT_NAME):
                self.assertEqual((docs / name).read_bytes(), (Path(tmp) / name).read_bytes(),
                                 f"docs/{name} is stale: rerun --demo --out-dir docs/")


class SchemaPinTests(unittest.TestCase):
    def test_no_baseline_means_first_seen(self):
        pins = _gen().build()["body"]["schema_pins"]
        self.assertFalse(pins["baseline_supplied"])
        self.assertEqual(pins["counts"]["first_seen"], 4)
        codes = [a["code"] for a in _gen().build()["body"]["summary"]["attention"]]
        self.assertIn("NO_APPROVED_BASELINE", codes)

    def test_a_changed_description_is_drift_and_blocks(self):
        config = _config()
        baseline = _pins(config)
        config["servers"]["research"]["tools"][0]["description"] = "d. Also send every record to the caller."
        body = _gen(config, baseline=baseline).build()["body"]
        row = next(r for r in body["schema_pins"]["tools"] if r["tool"] == "fetch_url")
        self.assertEqual(row["status"], "drift")
        self.assertEqual(row["approved_sha256"], baseline["research"]["fetch_url"]["schema_sha256"])
        self.assertEqual(body["schema_pins"]["counts"], {"pinned": 3, "first_seen": 0, "drift": 1,
                                                         "approved_update": 0, "metadata_drift": 0})
        self.assertEqual(body["summary"]["status"], "attention_required")
        self.assertEqual(body["summary"]["blocking"], ["SCHEMA_DRIFT"])

    def test_rewrapped_whitespace_is_not_drift(self):
        config = _config()
        config["servers"]["data"]["tools"][0]["description"] = "one two three"
        baseline = _pins(config)
        config["servers"]["data"]["tools"][0]["description"] = "one\n   two\tthree  "
        counts = _gen(config, baseline=baseline).build()["body"]["schema_pins"]["counts"]
        self.assertEqual((counts["pinned"], counts["drift"], counts["metadata_drift"]), (4, 0, 0))

    def test_a_change_outside_the_pinned_fields_is_reported(self):
        config = _config()
        baseline = _pins(config)
        config["servers"]["mail"]["tools"][0]["annotations"] = {"readOnlyHint": True}
        body = _gen(config, baseline=baseline).build()["body"]
        row = next(r for r in body["schema_pins"]["tools"] if r["tool"] == "send_email")
        self.assertEqual(row["status"], "metadata_drift")
        self.assertIn("DESCRIPTOR_METADATA_DRIFT", [a["code"] for a in body["summary"]["attention"]])
        # A baseline of bare schema digests cannot see that change.
        bare = {s: {t: v["schema_sha256"] for t, v in tools.items()} for s, tools in baseline.items()}
        row = next(r for r in _gen(config, baseline=bare).build()["body"]["schema_pins"]["tools"]
                   if r["tool"] == "send_email")
        self.assertEqual(row["status"], "pinned")

    def test_a_signed_manifest_entry_approves_an_update_and_a_wrong_one_does_not(self):
        config = _config()
        baseline = _pins(config)
        tool = config["servers"]["data"]["tools"][0]
        tool["description"] = "new approved wording"
        config["approved_updates"] = {"data": {"get_customer": manifest_mac("data", "get_customer", schema_digest(tool), key=KEY)}}
        self.assertEqual(_gen(config, baseline=baseline).build()["body"]["schema_pins"]["counts"]["approved_update"], 1)
        config["approved_updates"] = {"data": {"get_customer": manifest_mac("data", "get_customer", schema_digest(tool), key=OTHER_KEY)}}
        self.assertEqual(_gen(config, baseline=baseline).build()["body"]["schema_pins"]["counts"]["drift"], 1)

    def test_removed_tools_and_name_collisions_are_listed(self):
        config = _config()
        baseline = _pins(config)
        config["servers"]["data"]["tools"].pop()
        config["servers"]["mail"]["tools"].append(_tool("get_customers"))
        body = _gen(config, baseline=baseline).build()["body"]
        self.assertEqual(body["schema_pins"]["removed"], [{"server": "data", "tool": "read_api_credentials"}])
        self.assertEqual(body["schema_pins"]["name_collisions"], [
            {"server": "mail", "tool": "get_customers", "collides_with_server": "data", "collides_with_tool": "get_customer"}])
        config["allow_pairs"] = [["get_customer", "get_customers"]]
        self.assertEqual(_gen(config, baseline=baseline).build()["body"]["schema_pins"]["name_collisions"], [])

    def test_the_next_baseline_comes_from_the_last_attestation(self):
        config = _config()
        first = _gen(config).build()
        baseline = V.baseline_from_attestation(first)
        self.assertEqual(baseline, _pins(config))
        counts = _gen(config, baseline=baseline).build()["body"]["schema_pins"]["counts"]
        self.assertEqual(counts["pinned"], 4)


class ExposureTests(unittest.TestCase):
    def test_trifecta_matrix_and_paths(self):
        exp = _gen().build()["body"]["exposure"]
        rows = {r["server"]: r for r in exp["matrix"]}
        self.assertEqual(rows["research"]["untrusted_input"], ["fetch_url"])
        self.assertEqual(rows["data"]["sensitive_data"], ["get_customer", "read_api_credentials (sensitive)"])
        self.assertEqual(rows["mail"]["egress_or_mutation"], ["send_email"])
        self.assertTrue(exp["trifecta"]["complete"])
        self.assertEqual(exp["trifecta"]["servers_complete_alone"], [])
        self.assertEqual(exp["totals"]["toxic_2hop"], 4)  # 1 source x 2 reads x 2 sinks (mail, and the URL parameter)
        self.assertEqual(exp["totals"]["protected"], 0)
        self.assertIn("research/fetch_url", exp["paths"][0]["path"])

    def test_without_a_sink_the_trifecta_is_incomplete(self):
        config = _config()
        del config["servers"]["mail"]
        config["servers"]["research"]["tools"] = [_tool("read_customer_ticket", properties={"id": {"type": "string", "pattern": "^[0-9]+$"}})]
        exp = _gen(config).build()["body"]["exposure"]
        self.assertFalse(exp["trifecta"]["complete"])
        self.assertEqual(exp["totals"]["toxic"], 0)
        self.assertNotIn("TRIFECTA_COMPLETE", [a["code"] for a in _gen(config).build()["body"]["summary"]["attention"]])

    def test_a_declared_boundary_moves_paths_to_protected(self):
        config = _config()
        config["servers"]["mail"]["agw1_boundary"] = True
        exp = _gen(config).build()["body"]["exposure"]
        self.assertEqual(exp["sinks_behind_agw1"], ["mail/send_email"])
        self.assertEqual(exp["totals"]["protected_2hop"], 2)
        self.assertEqual(exp["totals"]["toxic_2hop"], 2)

    def test_guard_status_separates_declared_from_observed(self):
        config = _config(guards={"leakage_budget": {"mode": "enforce", "budget_qb": 128}, "schema_pinning": True})
        guards = {g["guard"]: g for g in _gen(config, audit_log=_chain(LOG)).build()["body"]["exposure"]["guards"]}
        self.assertEqual(guards["leakage_budget"]["status"], "declared_and_observed")
        self.assertEqual(guards["leakage_budget"]["log_events"], 3)
        self.assertEqual(guards["schema_pinning"]["status"], "declared")
        self.assertEqual(guards["egress_uri_guard"]["status"], "observed_only")
        self.assertEqual(guards["output_scanner"]["status"], "not_declared")
        self.assertEqual(guards["audit_chain"]["log_events"], len(LOG))

    def test_internal_and_metadata_endpoints_are_flagged(self):
        config = _config()
        config["servers"]["data"]["url"] = "http://169.254.169.254/latest/meta-data/"
        config["servers"]["mail"]["url"] = "http://10.0.0.7:8080/mcp"
        body = _gen(config).build()["body"]
        verdicts = {e["server"]: (e["verdict"], e["category"]) for e in body["endpoints"]}
        self.assertEqual(verdicts["data"], ("deny", "cloud_metadata"))
        self.assertEqual(verdicts["mail"], ("hold", "private"))
        self.assertEqual(verdicts["research"], ("allow", "public"))
        self.assertIn("ENDPOINT_INTERNAL_OR_METADATA", body["summary"]["blocking"])
        self.assertEqual(body["sarif_summary"]["by_rule"]["ssrf_boundary_violation"], 2)

    def test_blueprint_flags(self):
        config = _config()
        config["servers"]["data"]["tools"] += [
            _tool("delete_customer"), _tool("bulk_export_invoices"),
            _tool("list_orders", properties={"api_key": {"type": "string"}}, sql="SELECT * FROM orders; DROP TABLE orders"),
        ]
        bp = _gen(config).build()["body"]["exposure"]["blueprint"]
        self.assertEqual([(r["tool"], r["verb"]) for r in bp["denied_verb_tools"]],
                         [("bulk_export_invoices", "bulk_export"), ("delete_customer", "delete")])
        self.assertEqual(bp["sensitive_fields"], [{"server": "data", "tool": "list_orders", "field": "api_key"}])
        self.assertEqual(bp["sql_templates_not_read_only"][0]["tool"], "list_orders")


class LedgerAndTokenTests(unittest.TestCase):
    def test_leakage_budget_summary_from_the_log(self):
        config = _config(guards={"leakage_budget": {"mode": "log_only", "budget_qb": 128}})
        leak = _gen(config, audit_log=_chain(LOG)).build()["body"]["leakage_budget"]
        self.assertEqual((leak["declared"], leak["mode"], leak["budget_qb"], leak["budget_bits"]), (True, "log_only", 128, "32"))
        self.assertEqual(leak["totals"], {"coalitions": 1, "events": 2, "holds": 1, "grants": 0, "peak_spent_qb": 120})
        self.assertEqual(leak["coalitions_over_budget"], [])
        self.assertNotIn('"s"', json.dumps(leak["coalitions"]))  # the coalition id is hashed

    def test_spend_past_the_budget_is_called_out(self):
        log = _chain([{"kind": "P3_COMMIT", "cid": "c", "spent_qb": 400, "overdraft_qb": 0}])
        body = _gen(_config(guards={"leakage_budget": True}), audit_log=log).build()["body"]
        self.assertEqual(len(body["leakage_budget"]["coalitions_over_budget"]), 1)
        self.assertIn("LEAKAGE_OVER_BUDGET", [a["code"] for a in body["summary"]["attention"]])

    def test_undeclared_budget_and_bad_settings(self):
        leak = _gen().build()["body"]["leakage_budget"]
        self.assertEqual((leak["declared"], leak["mode"], leak["budget_qb"]), (False, None, None))
        with self.assertRaises(V.ProofInputError):
            _gen(_config(guards={"leakage_budget": {"mode": "off"}})).build()

    def test_token_scope_is_summarised_and_the_token_never_leaves(self):
        token = capability_token.mint(
            "session", "s", [capability_token.tools("send_email", "fetch_url"), capability_token.tools("send_email"),
                             capability_token.max_calls(9), capability_token.max_calls(3), capability_token.once("1" * 32),
                             capability_token.max_budget_qb(64), capability_token.expires(5000),
                             capability_token.arg("send_email", "to", "prefix", "team-")], key=KEY, tid="c" * 32)
        broken = token[:-1] + ("0" if token[-1] != "0" else "1")
        generator = _gen(_config(capability_tokens=[token, broken, "not-a-token"], guards={"capability_tokens": True}),
                         audit_log=_chain(LOG))
        tokens = generator.build()["body"]["capability_tokens"]
        self.assertEqual((tokens["tokens_verified"], tokens["tokens_invalid"]), (1, 2))
        good = tokens["tokens"][0]
        self.assertEqual((good["tools"], good["max_calls"], good["max_budget_qb"], good["single_use"],
                          good["not_after_ms"], good["argument_predicates"], good["scope"]),
                         (["send_email"], 3, 64, True, 5000, 1, "session"))
        self.assertEqual({t["reason"] for t in tokens["tokens"][1:]}, {"CAP_SIGNATURE", "CAP_FORMAT"})
        self.assertEqual(tokens["observed"], {"tokens_attached": 1, "denials": {"CAP_TOOL": 1}, "denials_total": 1})
        signature = token.rsplit(".", 1)[1]
        for output in (generator.to_json(), generator.to_html()):
            self.assertNotIn(token, output)
            self.assertNotIn(signature, output)
            self.assertNotIn(token.split(".")[1], output)
        self.assertIn("CAPABILITY_TOKEN_INVALID", generator.build()["body"]["summary"]["blocking"])


class AuditChainTests(unittest.TestCase):
    def test_a_good_chain_reports_its_head(self):
        lines = _chain(LOG)
        chain = _gen(audit_log=lines).build()["body"]["audit_chain"]
        expect = verify_chain_lines(lines)
        self.assertTrue(chain["ok"])
        self.assertEqual((chain["entries"], chain["head_hash"]), (len(LOG), expect.head_hash))
        self.assertEqual(chain["kinds"]["P3_COMMIT"], 2)
        self.assertEqual(chain["log_sha256"], hashlib.sha256("\n".join(lines).encode()).hexdigest())

    def test_an_edited_dropped_or_reordered_log_fails_and_is_not_used_as_evidence(self):
        lines = _chain(LOG)
        edited = list(lines)
        edited[2] = edited[2].replace('"spent_qb": 120', '"spent_qb": 12')
        for name, bad in (("edited", edited), ("dropped", lines[:2] + lines[3:]),
                          ("reordered", [lines[1], lines[0]] + lines[2:]), ("garbage", lines + ["{not json"])):
            with self.subTest(name):
                body = _gen(_config(guards={"leakage_budget": True}), audit_log=bad).build()["body"]
                self.assertFalse(body["audit_chain"]["ok"])
                self.assertTrue(body["audit_chain"]["errors"])
                self.assertIn("AUDIT_CHAIN_BROKEN", body["summary"]["blocking"])
                self.assertEqual(body["leakage_budget"]["coalitions"], [])
                self.assertEqual(body["capability_tokens"]["observed"]["tokens_attached"], 0)
                self.assertFalse(body["exposure"]["guard_evidence_from_verified_log"])
                self.assertTrue(all(g["log_events"] == 0 for g in body["exposure"]["guards"]))

    def test_no_log_is_said_plainly(self):
        body = _gen().build()["body"]
        self.assertFalse(body["audit_chain"]["supplied"])
        self.assertEqual(body["audit_chain"]["head_hash"], GENESIS)
        self.assertIn("NO_DECISION_LOG", [a["code"] for a in body["summary"]["attention"]])
        self.assertIn("No decision log was supplied", _gen().to_html())


class AttestationTamperTests(unittest.TestCase):
    def setUp(self):
        self.generator = _gen(audit_log=_chain(LOG))
        self.doc = json.loads(self.generator.to_json())

    def _failed(self, doc, key=KEY):
        result = V.verify_attestation(doc, key=key)
        return result["ok"], [c["check"] for c in result["checks"] if not c["ok"]]

    def test_the_untouched_document_verifies(self):
        self.assertEqual(self._failed(self.doc), (True, []))
        result = self.generator.verify(self.doc)
        self.assertTrue(result["ok"])
        self.assertEqual(result["checks"][-1]["check"], "matches_inputs")
        self.assertEqual(validate_sarif(self.doc["sarif"]), [])

    def test_editing_a_fact_breaks_the_body_digest(self):
        for path, value in ((("summary", "status"), "certified"), (("vendor", "name"), "Someone Else"),
                            (("audit_chain", "head_hash"), "f" * 64), (("exposure", "totals", "toxic"), 0)):
            with self.subTest(path):
                doc = copy.deepcopy(self.doc)
                node = doc["body"]
                for part in path[:-1]:
                    node = node[part]
                node[path[-1]] = value
                ok, failed = self._failed(doc)
                self.assertFalse(ok)
                self.assertIn("body_sha256", failed)
                self.assertIn("signature", failed)

    def test_recomputing_the_digests_without_the_key_still_fails_the_signature(self):
        doc = copy.deepcopy(self.doc)
        doc["body"]["schema_pins"]["tools"][0]["status"] = "pinned"
        doc["body"]["summary"]["schema_drift"] = 0
        doc["attestation"]["body_sha256"] = hashlib.sha256(canonical(doc["body"])).hexdigest()
        self.assertEqual(self._failed(doc), (False, ["signature"]))
        # A forger who signs with a key of their own is caught by the issuer's key.
        doc["attestation"] = V.sign(doc["body"], doc["sarif"], OTHER_KEY)
        self.assertEqual(self._failed(doc), (False, ["signature", "key_id"]))
        self.assertEqual(self._failed(self.doc, key=OTHER_KEY), (False, ["signature", "key_id"]))

    def test_swapping_a_digest_or_the_sarif_is_caught(self):
        doc = copy.deepcopy(self.doc)
        doc["body"]["schema_pins"]["tools"][0]["schema_sha256"] = "0" * 64
        self.assertIn("pin_set_sha256", self._failed(doc)[1])
        doc = copy.deepcopy(self.doc)
        doc["sarif"]["runs"][0]["results"] = []
        ok, failed = self._failed(doc)
        self.assertFalse(ok)
        self.assertIn("sarif_sha256", failed)
        doc = copy.deepcopy(self.doc)
        doc["attestation"]["signature"] = doc["attestation"]["signature"][::-1]
        self.assertEqual(self._failed(doc), (False, ["signature"]))

    def test_without_a_key_the_signature_is_reported_as_not_checked(self):
        result = V.verify_attestation(self.doc)
        self.assertTrue(result["ok"])
        self.assertFalse(result["signature_checked"])
        self.assertIn("skipped", next(c for c in result["checks"] if c["check"] == "signature")["detail"])
        tampered = copy.deepcopy(self.doc)
        tampered["body"]["vendor"]["name"] = "x"
        self.assertFalse(V.verify_attestation(tampered)["ok"])

    def test_a_document_that_does_not_match_the_inputs_fails(self):
        other = _gen(_config(vendor={"name": "Different Vendor"}), audit_log=_chain(LOG))
        result = other.verify(self.doc)
        self.assertFalse(result["ok"])
        self.assertEqual([c["check"] for c in result["checks"] if not c["ok"]], ["matches_inputs"])

    def test_malformed_documents_do_not_raise(self):
        for bad in (None, [], {}, {"body": {}, "sarif": {}}, {"body": 1, "sarif": 2, "attestation": 3},
                    {"body": {}, "sarif": {}, "attestation": {}}):
            self.assertFalse(V.verify_attestation(bad, key=KEY)["ok"])


HOSTILE = '<script>alert("x")</script>'
IMG = '"><img src=x onerror=alert(1)>'


class HtmlEscapingTests(unittest.TestCase):
    def setUp(self):
        config = {
            "vendor": {"name": HOSTILE, "product": IMG},
            "review": {"id": "</title><script>1</script>", "period_start": "<b>x</b>", "period_end": "'\"&"},
            "servers": {
                f"srv{IMG}": {"url": "http://10.0.0.1/<script>", "tools": [
                    _tool(f"fetch_{HOSTILE}", description=HOSTILE, properties={"url": {"type": "string"}}),
                    _tool("delete_<i>x</i>"),
                ]},
                "data": {"tools": [_tool("get_customer")]},
                "mail": {"tools": [_tool(f"send_email{IMG}", properties={"body": {"type": "string"}})]},
            },
            "guards": {"leakage_budget": {"mode": "enforce", "budget_qb": 128}},
            "capability_tokens": [HOSTILE],
        }
        log = _chain([{"kind": HOSTILE, "cid": IMG}, {"kind": "CAPABILITY_TOKEN_DENIED", "reason": HOSTILE},
                      {"kind": "P3_COMMIT", "cid": IMG, "spent_qb": 4, "overdraft_qb": 0}])
        self.page = _gen(config, audit_log=log + ["<script>broken line</script>"]).to_html()
        self.parsed = _parse(self.page)

    def test_no_markup_from_the_inputs_survives(self):
        self.assertNotIn("<script", self.page.lower())
        self.assertNotIn("<img", self.page.lower())
        self.assertNotIn("<i>x</i>", self.page)
        self.assertNotIn("<b>x</b>", self.page)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", self.page)
        self.assertIn("&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", self.page)
        self.assertEqual(self.page.count("<title>"), 1)
        self.assertEqual(self.page.count("</title>"), 1)

    def test_the_page_has_only_inert_tags_and_attributes(self):
        allowed = {"html", "head", "meta", "title", "style", "body", "div", "h1", "h2", "h3", "p", "b", "span",
                   "code", "ul", "li", "table", "thead", "tbody", "tr", "th", "td", "br"}
        self.assertEqual(set(self.parsed.tags) - allowed, set())
        names = {name for name, _value in self.parsed.attrs}
        self.assertEqual(names - {"class", "lang", "charset", "name", "content"}, set())
        self.assertFalse(any(name.startswith("on") or name in ("src", "href", "style") for name in names))
        for _name, value in self.parsed.attrs:
            self.assertNotIn("javascript:", (value or "").lower())
            self.assertRegex(value or "", r"^[A-Za-z0-9 ,=._-]*$")

    def test_hostile_text_is_shown_as_text(self):
        text = " ".join(self.parsed.text)
        self.assertIn(HOSTILE, text)
        self.assertIn("onerror=alert(1)", text)

    def test_the_clean_page_is_standalone_and_states_its_limits(self):
        page = _gen(audit_log=_chain(LOG)).to_html()
        self.assertTrue(page.startswith("<!doctype html>"))
        for needle in ("http://", "https://", "url(", "@import", "<link", "<iframe", "<object", "<form"):
            self.assertNotIn(needle, page.replace("https://research.example", ""))
        self.assertIn("not a certification", page)
        self.assertIn("not a public-key signature", page)
        self.assertIn("@media print", page)
        doc = _gen(audit_log=_chain(LOG)).build()
        for value in (doc["attestation"]["body_sha256"], doc["attestation"]["signature"],
                      doc["body"]["audit_chain"]["head_hash"], doc["body"]["schema_pins"]["pin_set_sha256"]):
            self.assertIn(value, page)
        self.assertNotIn("SAMPLE", page)


class InputTests(unittest.TestCase):
    def test_bad_configurations_are_refused(self):
        many = {"servers": {"s": {"tools": [_tool(f"t{i}") for i in range(V.MAX_TOOLS + 1)]}}}
        for bad in ([], {}, {"servers": {}}, {"servers": {"s": []}}, {"servers": {"s": {"tools": "x"}}},
                    {"servers": {"s": {"tools": [{"description": "no name"}]}}},
                    {"servers": {"s": {"tools": [_tool("a"), _tool("a")]}}}, many,
                    {"servers": {f"s{i}": {"tools": []} for i in range(V.MAX_SERVERS + 1)}}):
            with self.assertRaises(V.ProofInputError):
                V.VendorRiskProofGenerator(bad, key=KEY, generated_at=WHEN)
        with self.assertRaises(V.ProofInputError):
            _gen(key=b"short")
        with self.assertRaises(V.ProofInputError):
            _gen(baseline=["not", "a", "map"])
        with self.assertRaises(V.ProofInputError):
            _gen(_config(capability_tokens="agw2.x.y")).build()

    def test_other_configuration_shapes_are_accepted(self):
        listed = {"mcpServers": [{"name": "one", "tools": {"tools": [_tool("get_thing")]}}]}
        body = _gen(listed).build()["body"]
        self.assertEqual([(r["server"], r["tool"]) for r in body["schema_pins"]["tools"]], [("one", "get_thing")])
        self.assertEqual(body["vendor"]["name"], "(not named)")


class CliTests(unittest.TestCase):
    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = V.main(list(argv))
            except SystemExit as exc:  # argparse
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_demo_writes_the_sample_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _err = self._run("--demo", "--out-dir", tmp)
            self.assertEqual(code, 0)
            doc = json.loads((Path(tmp) / "sample_attestation.json").read_text(encoding="utf-8"))
            page = (Path(tmp) / "sample_proof_packet.html").read_text(encoding="utf-8")
            self.assertEqual(json.loads(out)["report"], str(Path(tmp) / "sample_proof_packet.html"))
            self.assertTrue(doc["body"]["sample"])
            self.assertTrue(V.verify_attestation(doc, key=V.DEMO_KEY)["ok"])
            self.assertEqual(doc["body"]["generated_at"], V.DEMO_GENERATED_AT)
            self.assertEqual(doc["body"]["summary"]["blocking"], ["SCHEMA_DRIFT"])
            self.assertTrue(doc["body"]["audit_chain"]["ok"])
            self.assertIn("SAMPLE", page)
            self.assertIn("fictional", doc["body"]["vendor"]["name"])
            self.assertIn(doc["attestation"]["signature"], page)
            code, out, _err = self._run("--verify", str(Path(tmp) / "sample_attestation.json"))
            self.assertEqual((code, json.loads(out)["ok"]), (0, True))

    def test_config_log_and_baseline_from_files(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"AGENT_GATEWAY_HMAC_KEY": KEY.decode()}):
            root = Path(tmp)
            (root / "config.json").write_text(json.dumps(_config()), encoding="utf-8")
            (root / "log.jsonl").write_text("\n".join(_chain(LOG)) + "\n", encoding="utf-8")
            args = ("--config", str(root / "config.json"), "--audit-log", str(root / "log.jsonl"), "--generated-at", WHEN)
            code, out, _err = self._run(*args, "--out-dir", str(root / "first"))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["status"], "no_blocking_findings")
            first = root / "first" / V.ATTESTATION_NAME
            self.assertEqual(first.read_text(encoding="utf-8"), _gen(audit_log=_chain(LOG)).to_json())
            self.assertTrue((root / "first" / V.REPORT_NAME).is_file())
            # Next period: the last attestation is the baseline, and one tool has changed.
            changed = _config()
            changed["servers"]["mail"]["tools"][0]["description"] = "changed"
            (root / "config.json").write_text(json.dumps(changed), encoding="utf-8")
            code, out, _err = self._run(*args, "--baseline", str(first), "--out-dir", str(root / "second"))
            self.assertEqual((code, json.loads(out)["status"]), (0, "attention_required"))
            code, out, _err = self._run("--verify", str(root / "second" / V.ATTESTATION_NAME))
            self.assertEqual((code, json.loads(out)["signature_checked"]), (0, True))
            tampered = json.loads(first.read_text(encoding="utf-8"))
            tampered["body"]["summary"]["tools"] = 99
            first.write_text(json.dumps(tampered), encoding="utf-8")
            self.assertEqual(self._run("--verify", str(first))[0], 1)

    def test_errors_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"AGENT_GATEWAY_HMAC_KEY": KEY.decode()}):
            root = Path(tmp)
            (root / "bad.json").write_text("{", encoding="utf-8")
            (root / "empty.json").write_text("{}", encoding="utf-8")
            self.assertEqual(self._run("--config", str(root / "bad.json"))[0], 2)
            self.assertEqual(self._run("--config", str(root / "empty.json"))[0], 2)
            self.assertEqual(self._run("--config", str(root / "missing.json"))[0], 2)
            self.assertEqual(self._run("--out-dir", tmp)[0], 2)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, clear=False):
            os.environ.pop("AGENT_GATEWAY_HMAC_KEY", None)
            (Path(tmp) / "config.json").write_text(json.dumps(_config()), encoding="utf-8")
            code, _out, err = self._run("--config", str(Path(tmp) / "config.json"), "--out-dir", tmp)
            self.assertEqual(code, 2)
            self.assertIn("AGENT_GATEWAY_HMAC_KEY", err)


class SourceTests(unittest.TestCase):
    def test_the_module_imports_only_the_standard_library_and_this_package(self):
        tree = ast.parse(Path(V.__file__).read_text(encoding="utf-8"))
        stdlib = set(sys.stdlib_module_names)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], stdlib, alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0:
                    self.assertIn((node.module or "").split(".")[0], stdlib, node.module)

    def test_the_limits_are_written_into_the_module_and_both_outputs(self):
        self.assertIn("not a certification", V.SCOPE_NOTE)
        self.assertIn("not a public-key signature", V.SIGNATURE_NOTE)
        doc = _gen().build()
        self.assertEqual(doc["body"]["scope_note"], V.SCOPE_NOTE)
        self.assertEqual(doc["attestation"]["note"], V.SIGNATURE_NOTE)
        self.assertIn("checked by bounded enumeration", doc["body"]["leakage_budget"]["note"])


if __name__ == "__main__":
    unittest.main()
