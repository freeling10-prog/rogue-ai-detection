"""HardenedMcpBlueprint: read-only queries, redaction, mutation-verb denial, confirmed writes, audit chain."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent_gateway.audit_chain import verify_chain_file
from agent_gateway.mcp_blueprint import (
    REDACTED,
    HardenedMcpBlueprint,
    validate_read_only_sql,
)
from agent_gateway.pep import PolicyEngine
from tests.conftest import KEY_A


@pytest.fixture()
def db():
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE customers (id INTEGER, email TEXT, plan TEXT, api_key TEXT, ssn TEXT)")
    con.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?)",
                    [(i, f"user{i}@example.com", "pro" if i % 2 else "free", f"sk_live_{i:04d}", f"123-45-{i:04d}")
                     for i in range(250)])
    yield con
    con.close()


@pytest.fixture()
def bp(engine: PolicyEngine, state_dir: Path, db):
    tasks: list[dict] = []

    def run(sql, params, limit):
        return [dict(r) for r in db.execute(f"{sql} LIMIT {int(limit)}", params)]

    b = HardenedMcpBlueprint(engine, KEY_A, audit_log=state_dir / "blueprint-audit.jsonl")
    b.register_query("customers_by_plan", "SELECT id, email, plan, api_key, ssn FROM customers WHERE plan = :plan",
                     run, description="Customers on a plan.")
    b.register_query("all_customers_unbounded", "SELECT * FROM customers", lambda sql, p, n: [
        dict(r) for r in db.execute(sql)])  # executor ignores the limit; the harness still caps rows
    b.register_lookup("hubspot_contact_lookup", lambda a: {
        "contact": {"email": a["email"], "owner": "ops", "hubspotToken": "pat-na1-abc",
                    "notes": [{"text": "renewal in May", "password_hint": "blue"}]}})
    b.register_write("create_followup_task", lambda a: tasks.append(a) or {"task_id": len(tasks)})
    b.register_lookup("stripe_refund_payment", lambda a: {"refunded": True})  # registered but never callable
    b.tasks = tasks
    return b


def test_parameterized_lookup_redacts_sensitive_fields(bp: HardenedMcpBlueprint):
    res = bp.call("s1", "customers_by_plan", {"plan": "pro", "limit": 5})
    assert res.ok and res.rule_code == "COMPLIANT" and res.rows == 5
    assert all(r["plan"] == "pro" and r["api_key"] == REDACTED and r["ssn"] == REDACTED for r in res.result)
    assert res.result[0]["email"].endswith("@example.com")
    assert res.redacted_fields == 10

    nested = bp.call("s1", "hubspot_contact_lookup", {"email": "a@example.com"})
    assert nested.ok and nested.redacted_fields == 2
    assert nested.result["contact"]["hubspotToken"] == REDACTED
    assert nested.result["contact"]["notes"][0]["password_hint"] == REDACTED
    assert nested.result["contact"]["owner"] == "ops"


def test_parameters_are_bound_not_interpolated(bp: HardenedMcpBlueprint):
    res = bp.call("s1", "customers_by_plan", {"plan": "pro' OR '1'='1", "limit": 10})
    assert res.ok and res.rows == 0


def test_row_cap_enforced(bp: HardenedMcpBlueprint):
    over = bp.call("s1", "customers_by_plan", {"plan": "free", "limit": 101})
    assert not over.ok and over.rule_code == "ROW_LIMIT_EXCEEDED"
    default = bp.call("s1", "all_customers_unbounded", {})
    assert default.ok and default.rows == 100  # executor returned 250; the harness kept 100
    assert bp.call("s1", "customers_by_plan", {"plan": "free", "limit": True}).rule_code == "QUERY_PARAMETER_INVALID"
    assert bp.call("s1", "customers_by_plan", {"plan": {"$ne": 1}}).rule_code == "QUERY_PARAMETER_INVALID"
    assert bp.call("s1", "customers_by_plan", {"plan": "pro", "sql": "x"}).rule_code == "QUERY_PARAMETER_INVALID"
    with pytest.raises(ValueError):
        HardenedMcpBlueprint(bp.engine, KEY_A, audit_log=bp.chain.path, max_rows=500)


@pytest.mark.parametrize("sql", [
    "DELETE FROM customers",
    "SELECT * FROM customers; DROP TABLE customers",
    "WITH x AS (SELECT 1) UPDATE customers SET plan = 'free'",
    "SELECT * FROM customers -- comment",
    "PRAGMA table_info(customers)",
])
def test_non_read_only_templates_refused_at_registration(sql):
    with pytest.raises(ValueError):
        validate_read_only_sql(sql)


@pytest.mark.parametrize("tool", ["stripe_refund_payment", "delete_customer", "bulkExportContacts",
                                  "cancel_subscription", "drop_table", "truncate_logs"])
def test_unapproved_mutation_verbs_denied(bp: HardenedMcpBlueprint, tool):
    res = bp.call("s1", tool, {"id": 1})
    assert not res.ok and res.rule_code == "MUTATION_VERB_DENIED"


def test_unlisted_tool_denied(bp: HardenedMcpBlueprint):
    assert bp.call("s1", "run_shell", {"cmd": "ls"}).rule_code == "TOOL_NOT_ALLOWLISTED"


def test_confirmed_write(bp: HardenedMcpBlueprint):
    args = {"contact": "a@example.com", "title": "Renewal call"}
    assert bp.call("s1", "create_followup_task", args).rule_code == "CONFIRMATION_REQUIRED"
    assert bp.call("s1", "create_followup_task", args, "agc1.x.1.y").rule_code == "CONFIRMATION_INVALID"
    token = bp.issue_confirmation("s1", "create_followup_task", args)
    # Bound to the exact arguments and session.
    assert bp.call("s1", "create_followup_task", {**args, "title": "Other"}, token).rule_code == "CONFIRMATION_INVALID"
    assert bp.call("s2", "create_followup_task", args, token).rule_code == "CONFIRMATION_INVALID"
    ok = bp.call("s1", "create_followup_task", args, token)
    assert ok.ok and ok.result == {"task_id": 1} and bp.tasks == [args]
    assert bp.call("s1", "create_followup_task", args, token).rule_code == "CONFIRMATION_REPLAYED"
    assert len(bp.tasks) == 1


def test_approved_verb_still_needs_confirmation(engine: PolicyEngine, state_dir: Path):
    b = HardenedMcpBlueprint(engine, KEY_A, audit_log=state_dir / "b.jsonl", approved_verbs=["cancel"])
    b.register_write("cancel_trial", lambda a: {"cancelled": a["id"]})
    assert b.call("s", "cancel_trial", {"id": 7}).rule_code == "CONFIRMATION_REQUIRED"
    assert b.call("s", "cancel_trial", {"id": 7}, b.issue_confirmation("s", "cancel_trial", {"id": 7})).ok


def test_pep_gate_applies(bp: HardenedMcpBlueprint):
    # Untrusted ingest taints the session; the PEP then holds the write even with a valid confirmation.
    bp.engine.evaluate_call(KEY_A, "s3", "read_external_url", {"url": "http://127.0.0.1/p"})
    args = {"contact": "a@example.com", "title": "x"}
    res = bp.call("s3", "create_followup_task", args, bp.issue_confirmation("s3", "create_followup_task", args))
    assert not res.ok and res.rule_code == "POLICY_DENIED" and "post_taint_outbound_gated" in res.message


def test_jsonrpc_surface(bp: HardenedMcpBlueprint):
    listed = bp.handle_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, "s1")
    names = [t["name"] for t in listed["result"]["tools"]]
    assert "customers_by_plan" in names
    schema = listed["result"]["tools"][0]["inputSchema"]
    assert schema["properties"]["limit"]["maximum"] == 100 and schema["required"] == ["plan"]
    denied = bp.handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                "params": {"name": "delete_customer", "arguments": {"id": 1}}}, "s1")
    assert denied["error"]["data"]["rule_code"] == "MUTATION_VERB_DENIED"
    args = {"contact": "b@example.com", "title": "t"}
    tok = bp.issue_confirmation("s1", "create_followup_task", args)
    ok = bp.handle_jsonrpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
        "name": "create_followup_task", "arguments": args, "_meta": {"agentgate/confirmation_token": tok}}}, "s1")
    assert ok["result"]["isError"] is False and ok["result"]["_meta"]["agentgate/rule_code"] == "COMPLIANT"


def test_audit_chain_end_to_end(bp: HardenedMcpBlueprint):
    bp.call("s1", "customers_by_plan", {"plan": "pro", "limit": 3})
    bp.call("s1", "stripe_refund_payment", {"charge": "ch_1"})
    bp.call("s1", "create_followup_task", {"title": "x"})
    args = {"title": "y"}
    last = bp.call("s1", "create_followup_task", args, bp.issue_confirmation("s1", "create_followup_task", args))
    report = verify_chain_file(bp.chain.path)
    assert report.ok and report.entries == 5  # 4 calls + 1 confirmation issued
    assert report.head_hash == last.audit_entry_hash
    lines = bp.chain.path.read_text().splitlines()
    assert "sk_live_" not in "".join(lines)  # outputs are not logged, only verdicts and scrubbed args
    lines[1] = lines[1].replace('"DENY"', '"ALLOW"')
    bp.chain.path.write_text("\n".join(lines) + "\n")
    assert verify_chain_file(bp.chain.path).ok is False
