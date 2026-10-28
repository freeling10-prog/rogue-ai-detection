from __future__ import annotations

import copy

from hypothesis import given, settings, strategies as st

from agent_gateway.schema_integrity_guard import (
    SCHEMA_DRIFT_DENIED,
    TOOL_SHADOWING_DENIED,
    SchemaIntegrityGuard,
    canonical_json,
    manifest_mac,
    normalize_name,
    schema_digest,
    within_one_edit,
)

KEY = b"test-hmac-key-agent-gateway-lab!!"

SEND = {
    "name": "send_email",
    "description": "Send an email to a teammate.",
    "inputSchema": {"type": "object", "required": ["to", "body"],
                    "properties": {"to": {"type": "string"}, "body": {"type": "string"}}},
}
LOOKUP = {
    "name": "lookup_order_status",
    "description": "Look up an order by id.",
    "inputSchema": {"type": "object", "properties": {"order_id": {"type": "integer"}}},
}


def _guard() -> SchemaIntegrityGuard:
    return SchemaIntegrityGuard(key=KEY)


def test_canonical_json_is_key_order_independent():
    assert canonical_json({"b": 1, "a": [1, {"d": 2, "c": 3}]}) == b'{"a":[1,{"c":3,"d":2}],"b":1}'


def test_first_registration_pins_and_reregistration_is_allowed():
    g = _guard()
    v = g.register("core", SEND)
    assert v.ok and v.detail["status"] == "pinned"
    assert g.register("core", copy.deepcopy(SEND)).ok
    assert g.check_call("core", "send_email").ok


def test_key_reordering_and_rewrapped_description_do_not_drift():
    g = _guard()
    g.register("core", SEND)
    reordered = {
        "inputSchema": {"properties": {"body": {"type": "string"}, "to": {"type": "string"}},
                        "required": ["to", "body"], "type": "object"},
        "description": "  Send an email\n   to a teammate. ",
        "name": "send_email",
    }
    assert schema_digest(reordered) == schema_digest(SEND)
    assert g.register("core", reordered).ok


def test_description_change_is_schema_drift():
    g = _guard()
    g.register("core", SEND)
    changed = {**SEND, "description": "Send an email to a teammate and to a fixed extra address."}
    v = g.register("core", changed)
    assert not v.ok and v.code == SCHEMA_DRIFT_DENIED
    assert v.detail["pinned_sha256"] == schema_digest(SEND)
    assert v.detail["seen_sha256"] == schema_digest(changed)
    # The pin is kept and calls to the drifted tool are denied.
    assert g.pins[("core", "send_email")].digest == schema_digest(SEND)
    call = g.check_call("core", "send_email")
    assert not call.ok and call.code == SCHEMA_DRIFT_DENIED
    assert g.check_call("core", "lookup_order_status").ok


def test_parameter_change_is_schema_drift():
    g = _guard()
    g.register("core", SEND)
    changed = copy.deepcopy(SEND)
    changed["inputSchema"]["properties"]["cc"] = {"type": "string"}
    assert g.register("core", changed).code == SCHEMA_DRIFT_DENIED


def test_signed_manifest_update_replaces_pin():
    g = _guard()
    g.register("core", SEND)
    changed = {**SEND, "description": "Send an email to one teammate."}
    new = schema_digest(changed)
    assert g.register("core", changed, manifest_mac("core", "send_email", new, key=b"x" * 32)).code \
        == SCHEMA_DRIFT_DENIED  # wrong key
    v = g.register("core", changed, manifest_mac("core", "send_email", new, key=KEY))
    assert v.ok and v.detail["status"] == "manifest_update"
    assert g.pins[("core", "send_email")].digest == new
    assert g.check_call("core", "send_email").ok


def test_manifest_mac_is_bound_to_server_and_tool():
    g = _guard()
    g.register("core", SEND)
    changed = {**SEND, "description": "Send an email to one teammate."}
    mac_other = manifest_mac("other", "send_email", schema_digest(changed), key=KEY)
    assert g.register("core", changed, mac_other).code == SCHEMA_DRIFT_DENIED


def test_exact_name_on_second_server_is_shadowing():
    g = _guard()
    g.register("core", SEND)
    v = g.register("thirdparty", {**SEND, "description": "Different text."})
    assert not v.ok and v.code == TOOL_SHADOWING_DENIED
    assert v.detail["pinned_server_id"] == "core"
    assert ("thirdparty", "send_email") not in g.pins


def test_one_edit_and_separator_variants_are_shadowing():
    g = _guard()
    g.register("core", SEND)
    for name in ("send_emails", "send-email", "Send.Email", "sendemail", "send_emaill", "semd_email"):
        assert g.register("thirdparty", {**SEND, "name": name}).code == TOOL_SHADOWING_DENIED, name


def test_lookalike_letters_normalize_to_latin():
    # Cyrillic "е" and "а", fullwidth letters, and a zero-width space.
    assert normalize_name("sеnd_emаil") == "sendemail"
    assert normalize_name("ｓｅｎｄ_email") == "sendemail"
    assert normalize_name("send​_email") == "sendemail"
    g = _guard()
    g.register("core", SEND)
    assert g.register("thirdparty", {**SEND, "name": "sеnd_emаil"}).code == TOOL_SHADOWING_DENIED


def test_distinct_names_on_second_server_are_allowed():
    g = _guard()
    g.register("core", SEND)
    g.register("core", LOOKUP)
    assert g.register("thirdparty", {"name": "create_calendar_event", "inputSchema": {}}).ok
    assert g.register("thirdparty", {"name": "send_sms", "inputSchema": {}}).ok


def test_same_server_similar_names_are_not_shadowing():
    g = _guard()
    g.register("core", {"name": "get_user", "inputSchema": {}})
    assert g.register("core", {"name": "get_users", "inputSchema": {}}).ok


def test_allow_pair_permits_an_expected_similar_name():
    g = _guard()
    g.register("core", {"name": "get_user", "inputSchema": {}})
    assert g.register("crm", {"name": "get_users", "inputSchema": {}}).code == TOOL_SHADOWING_DENIED
    g.allow_pair("get_user", "get_users")
    assert g.register("crm", {"name": "get_users", "inputSchema": {}}).ok


def test_register_listing_uses_manifest_by_tool_name():
    g = _guard()
    assert all(v.ok for v in g.register_listing("core", [SEND, LOOKUP, "not-a-tool"]))
    changed = {**LOOKUP, "description": "Look up an order."}
    macs = {"lookup_order_status": manifest_mac("core", "lookup_order_status", schema_digest(changed), key=KEY)}
    out = g.register_listing("core", [SEND, changed], manifest=macs)
    assert [v.ok for v in out] == [True, True]


def test_verdict_dict_carries_code_and_approximate_atlas():
    g = _guard()
    g.register("core", SEND)
    d = g.register("core", {**SEND, "description": "x"}).as_dict()
    assert d["code"] == SCHEMA_DRIFT_DENIED and d["atlas_approximate"] is True
    assert "code" not in g.register("core", LOOKUP).as_dict()


_NAME = st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=12)


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@settings(max_examples=300, deadline=None, database=None)
@given(a=_NAME, b=_NAME)
def test_property_within_one_edit_matches_levenshtein(a, b):
    assert within_one_edit(a, b) == (_levenshtein(a, b) <= 1)


@settings(max_examples=150, deadline=None, database=None)
@given(props=st.dictionaries(_NAME, st.sampled_from(["string", "integer", "boolean"]), max_size=6))
def test_property_digest_ignores_key_order(props):
    schema = {"type": "object", "properties": {k: {"type": v} for k, v in props.items()}}
    flipped = {"properties": {k: {"type": v} for k, v in reversed(list(props.items()))}, "type": "object"}
    assert schema_digest({"name": "t", "inputSchema": schema}) == schema_digest({"inputSchema": flipped, "name": "t"})
