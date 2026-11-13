"""Module 2 scaffold: ``agw2`` capability tokens.

The attenuation and counter properties are checked by bounded enumeration
within the bounds written next to each case. Nothing outside those bounds
is claimed.
"""
from __future__ import annotations

import base64
import itertools
import json

import pytest

from agent_gateway import capability_token as T
from agent_gateway.capability_token import Request, Token, TokenLedger
from agent_gateway.common import Denied
from agent_gateway.leakage_budget import Constant, Enum, FieldSchema, P3Config, SelectionManifest
from agent_gateway.pep import CAPABILITY_TOKEN_DENIED, PolicyEngine, _V12_CODES
from agent_gateway.sarif_export import RULES, _LOG_KIND_RULES
from tests.conftest import KEY_A, KEY_B

KEY = b"k" * 32
TID = "0" * 32
NONCE = "1" * 32


def _req(session="s", tool="a", dest="x", args=None, now=10, coalition=(), charge=0) -> Request:
    return Request(session_id=session, tool=tool, destination=dest,
                   arguments={"v": 0} if args is None else args, now_ms=now,
                   coalition=frozenset(coalition), charge_qb=charge)


def _reason(fn, *args):
    try:
        fn(*args)
    except Denied as exc:
        return str(exc)
    return None


def _body(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _forge(body: dict, signature: str, *, raw: bytes | None = None) -> str:
    blob = T.canonical(body) if raw is None else raw
    return f"agw2.{base64.urlsafe_b64encode(blob).decode().rstrip('=')}.{signature}"


# --- chain -------------------------------------------------------------------

def test_mint_attenuate_verify_roundtrip():
    root = T.mint("session", "s", [T.tools("a", "b")], key=KEY, tid=TID)
    child = T.attenuate(root, T.tools("a"), T.max_calls(2))  # no key needed
    v_root, v_child = T.verify(root, key=KEY), T.verify(child, key=KEY)
    assert v_child.token.caveats == (T.tools("a", "b"), T.tools("a"), T.max_calls(2))
    assert T.extends(v_root.token, v_child.token) and not T.extends(v_child.token, v_root.token)
    assert v_child.tags[0] == v_root.tags[0] == v_root.token.signature
    assert v_child.root_tag == v_root.root_tag
    named = T.mint("session", "customer-7", key=KEY, tid=TID)
    assert "customer-7" not in json.dumps(_body(named))  # the session id is hashed
    assert T.mint("session", "s", [T.tools("a", "b")], key=KEY, tid=TID) == root


def test_a_tampered_or_malformed_token_does_not_verify():
    token = T.attenuate(T.mint("session", "s", [T.tools("a", "b")], key=KEY, tid=TID), T.max_calls(1))
    body, sig = _body(token), token.rsplit(".", 1)[1]
    assert _reason(lambda: T.verify(token, key=b"z" * 32)) == "CAP_SIGNATURE"
    dropped = {**body, "caveats": body["caveats"][:1]}
    assert _reason(lambda: T.verify(_forge(dropped, sig), key=KEY)) == "CAP_SIGNATURE"
    swapped = {**body, "caveats": body["caveats"][::-1]}
    assert _reason(lambda: T.verify(_forge(swapped, sig), key=KEY)) == "CAP_SIGNATURE"
    widened = {**body, "caveats": [T.tools("a", "b", "c"), body["caveats"][1]]}
    assert _reason(lambda: T.verify(_forge(widened, sig), key=KEY)) == "CAP_SIGNATURE"
    rescoped = {**body, "scope": {"kind": "session", "id": T.scope_hash("other")}}
    assert _reason(lambda: T.verify(_forge(rescoped, sig), key=KEY)) == "CAP_SIGNATURE"
    spaced = json.dumps(body, sort_keys=True).encode()  # same content, not canonical
    assert _reason(lambda: T.verify(_forge(body, sig, raw=spaced), key=KEY)) == "CAP_NOT_CANONICAL"
    duplicate = T.canonical(body).replace(b'"v":2', b'"v":2,"v":2')
    assert _reason(lambda: T.verify(_forge(body, sig, raw=duplicate), key=KEY)) == "CAP_FORMAT"
    for bad in ("", "agw1.x.y", "agw2.!!.%s" % sig, "agw2.e30." + sig, token[:-1], token + "0", 7, None,
                "agw2." + "A" * 20000 + "." + sig):
        assert _reason(lambda: T.verify(bad, key=KEY)) in ("CAP_FORMAT", "CAP_SIGNATURE"), bad


@pytest.mark.parametrize("caveat", [
    {"t": "allow_everything"}, {"t": "tools", "allow": []}, {"t": "tools", "allow": ["b", "a"]},
    {"t": "tools", "allow": ["a"], "extra": 1}, {"t": "calls", "max": -1}, {"t": "calls", "max": True},
    {"t": "calls", "max": 1.5}, {"t": "exp"}, {"t": "once", "nonce": "xyz"},
    {"t": "arg", "tool": "a", "path": ["v"], "op": "matches", "value": ".*"},
    {"t": "arg", "tool": "a", "path": [], "op": "eq", "value": 1},
    {"t": "arg", "tool": "a", "path": ["v"], "op": "absent", "value": 1},
    {"t": "arg", "tool": "a", "path": ["v"], "op": "range", "value": [5, 1]},
    {"t": "arg", "tool": "a", "path": ["v"], "op": "eq", "value": {"nested": 1}},
    {"t": "budget_qb", "max": "128"}, "tools", None,
])
def test_a_caveat_outside_the_vocabulary_fails_closed(caveat):
    """Unlike agw1, where an unknown caveat verifies and is ignored."""
    with pytest.raises(Denied):
        T.check_caveat(caveat)
    root = T.mint("session", "s", key=KEY, tid=TID)
    with pytest.raises(Denied):
        T.attenuate(root, caveat)
    # A holder who folds the caveat in by hand still gets a token that does not parse.
    import hashlib
    import hmac as _hmac
    try:
        blob = T.canonical(caveat)
    except (TypeError, ValueError):
        return
    tag = _hmac.new(bytes.fromhex(root.rsplit(".", 1)[1]), blob, hashlib.sha256).hexdigest()
    forged = _forge({**_body(root), "caveats": [caveat]}, tag)
    assert _reason(lambda: T.verify(forged, key=KEY)) in ("CAP_CAVEAT", "CAP_CAVEAT_UNKNOWN", "CAP_FORMAT")


def test_limits():
    root = T.mint("session", "s", key=KEY, tid=TID)
    full = T.attenuate(root, *[T.max_calls(i) for i in range(T.MAX_CAVEATS)])
    assert _reason(T.attenuate, full, T.max_calls(1)) == "CAP_LIMIT"
    assert _reason(lambda: T.mint("session", "s", [T.max_calls(1)] * 33, key=KEY)) == "CAP_LIMIT"
    assert _reason(lambda: T.mint("tenant", "s", key=KEY)) == "CAP_SCOPE"
    assert _reason(lambda: T.mint("session", "", key=KEY)) == "CAP_SCOPE"


# --- stateless caveats -------------------------------------------------------

def _tok(*caveats, kind="session", anchor="s") -> Token:
    return Token(TID, kind, T.scope_hash(anchor), tuple(caveats), "")


def test_each_caveat_refuses_what_it_names():
    assert T.refusal(_tok(), _req()) is None
    assert T.refusal(_tok(), _req(session="t")) == "CAP_SCOPE"
    assert T.refusal(_tok(T.tools("a")), _req(tool="b")) == "CAP_TOOL"
    assert T.refusal(_tok(T.destinations("x", "")), _req(dest="y")) == "CAP_DESTINATION"
    assert T.refusal(_tok(T.destinations("x", "")), _req(dest="")) is None
    assert T.refusal(_tok(T.expires(10)), _req(now=10)) is None
    assert T.refusal(_tok(T.expires(10)), _req(now=11)) == "CAP_EXPIRED"
    coalition = _tok(kind="coalition", anchor="lead")
    assert T.refusal(coalition, _req(session="w1")) == "CAP_SCOPE"
    assert T.refusal(coalition, _req(session="w1", coalition={"lead", "w1"})) is None
    assert T.refusal(coalition, _req(session="lead")) is None
    narrowed = _tok(T.only_session("w1"), kind="coalition", anchor="lead")
    assert T.refusal(narrowed, _req(session="w1", coalition={"lead", "w1"})) is None
    assert T.refusal(narrowed, _req(session="w2", coalition={"lead", "w1", "w2"})) == "CAP_SCOPE"


@pytest.mark.parametrize("caveat, good, bad", [
    (T.arg("a", "v", "eq", 1), [{"v": 1}], [{"v": 2}, {"v": True}, {"v": "1"}, {}]),
    (T.arg("a", "v", "in", ["x", 3, None]), [{"v": "x"}, {"v": 3}, {"v": None}], [{"v": "y"}, {"v": False}, {}]),
    (T.arg("a", "to", "prefix", "team-"), [{"to": "team-a"}], [{"to": "xteam-a"}, {"to": 5}, {}]),
    (T.arg("a", "body", "max_len", 3), [{"body": "abc"}, {"body": [1, 2, 3]}],
     [{"body": "abcd"}, {"body": "é" * 2}, {"body": 1}, {}]),
    (T.arg("a", "n", "range", [1, 3]), [{"n": 1}, {"n": 3}], [{"n": 0}, {"n": 4}, {"n": True}, {"n": "2"}, {}]),
    (T.arg("a", "cc", "absent"), [{}, {"v": 1}], [{"cc": None}, {"cc": "x"}]),
    (T.arg("a", ["opt", "mode"], "eq", "ro"), [{"opt": {"mode": "ro"}}], [{"opt": {"mode": "rw"}}, {"opt": "ro"}, {}]),
    (T.arg("*", "v", "eq", 1), [{"v": 1}], [{"v": 2}]),
])
def test_argument_predicates(caveat, good, bad):
    for arguments in good:
        assert T.refusal(_tok(caveat), _req(args=arguments)) is None, arguments
    for arguments in bad:
        assert T.refusal(_tok(caveat), _req(args=arguments)) == "CAP_ARGUMENT", arguments
    if caveat["tool"] != "*":
        # A predicate for tool "a" says nothing about tool "b".
        assert T.refusal(_tok(caveat), _req(tool="b", args=bad[0])) is None


# --- bounded enumeration: attenuation only narrows ---------------------------
#
# Bounds: every chain of 0..3 caveats over the 9-caveat alphabet below (820
# chains), every one-caveat extension of each (7,380 pairs), against all 96
# requests in REQUESTS. Stateless caveats and scope only.

ALPHABET = (
    T.tools("a", "b"), T.tools("a"), T.destinations("x"), T.expires(10),
    T.arg("a", "v", "eq", 0), T.arg("*", "v", "range", [0, 1]), T.arg("b", "v", "absent"),
    T.only_session("s"), T.arg("a", "v", "in", [1, 5]),
)
REQUESTS = tuple(
    _req(session=session, tool=tool, dest=dest, args=arguments, now=now, coalition={"s", "t"})
    for session in ("s", "t") for tool in ("a", "b", "c") for dest in ("x", "y")
    for arguments in ({"v": 0}, {"v": 1}, {"v": 5}, {}) for now in (10, 99)
)


def _admitted(caveats, kind="coalition") -> frozenset:
    token = _tok(*caveats, kind=kind, anchor="s")
    return frozenset(i for i, request in enumerate(REQUESTS) if T.refusal(token, request) is None)


def test_enumeration_an_extension_admits_a_subset_of_its_prefix():
    assert len(REQUESTS) == 96  # 2 sessions x 3 tools x 2 destinations x 4 argument objects x 2 times
    single = {i: _admitted((caveat,)) for i, caveat in enumerate(ALPHABET)}
    everything = _admitted(())
    assert everything == frozenset(range(len(REQUESTS)))
    chains = pairs = strict = 0
    for length in range(0, 4):
        for picks in itertools.product(range(len(ALPHABET)), repeat=length):
            chain = tuple(ALPHABET[i] for i in picks)
            base = _admitted(chain)
            chains += 1
            # The chain admits exactly what every one of its caveats admits, in any order.
            expect = everything
            for i in picks:
                expect &= single[i]
            assert base == expect, picks
            for extra, caveat in enumerate(ALPHABET):
                grown = _admitted(chain + (caveat,))
                assert grown <= base, (picks, extra)
                strict += grown < base
                pairs += 1
    assert (chains, pairs) == (820, 7380)
    assert strict > 0 and all(single[i] < everything for i in single)


# Bounds: every chain of 0..2 caveats over the first five alphabet caveats (31
# chains). The forger holds the token and so its final tag, and may also fold
# any of those caveats onto that tag (6 tags). Candidate caveat lists: every
# list of 0..3 of those caveats (156). A candidate verifies only when it is
# the chain itself or the chain plus the caveat whose tag was used.

def test_enumeration_a_holder_can_only_append():
    import hashlib
    import hmac as _hmac

    forge = ALPHABET[:5]
    lists = [tuple(p) for n in range(0, 4) for p in itertools.product(range(len(forge)), repeat=n)]
    checked = accepted = 0
    for chain in (c for c in lists if len(c) <= 2):
        token = T.mint("session", "s", [forge[i] for i in chain], key=KEY, tid=TID)
        final = token.rsplit(".", 1)[1]
        head = {k: v for k, v in _body(token).items() if k != "caveats"}
        known = {final: chain}
        for extra, caveat in enumerate(forge):
            tag = _hmac.new(bytes.fromhex(final), T.canonical(caveat), hashlib.sha256).hexdigest()
            known[tag] = chain + (extra,)
        for candidate in lists:
            body = {**head, "caveats": [forge[i] for i in candidate]}
            for tag, honest in known.items():
                checked += 1
                ok = _reason(lambda: T.verify(_forge(body, tag), key=KEY)) is None
                assert ok == (candidate == honest), (chain, candidate)
                accepted += ok
    assert accepted == 31 * 6
    assert checked == 31 * 156 * 6


# --- counters ----------------------------------------------------------------

def test_calls_once_and_budget_are_shared_by_every_derived_token():
    ledger = TokenLedger(key=KEY)
    parent = T.mint("coalition", "lead", [T.max_calls(2), T.max_budget_qb(100)], key=KEY, tid=TID)
    worker = T.attenuate(parent, T.only_session("w1"), T.tools("a"))
    single = T.attenuate(parent, T.once(NONCE))
    lead = dict(session="lead")
    w1 = dict(session="w1", coalition={"lead", "w1"})
    ledger.commit(ledger.reserve(worker, _req(charge=60, **w1)))
    assert _reason(ledger.reserve, parent, _req(charge=41, **lead)) == "CAP_BUDGET_EXHAUSTED"
    held = ledger.reserve(single, _req(charge=40, **lead))
    # In flight: the last call and the single use are taken until this settles.
    assert _reason(ledger.reserve, parent, _req(charge=0, **lead)) == "CAP_CALLS_EXHAUSTED"
    ledger.abort(held)
    assert _reason(ledger.commit, held) == "CAP_UNKNOWN_RESERVATION"
    ledger.commit(ledger.reserve(single, _req(charge=40, **lead)))
    assert _reason(ledger.reserve, single, _req(**lead)) in ("CAP_CALLS_EXHAUSTED", "CAP_USED")
    assert _reason(ledger.reserve, worker, _req(**w1)) == "CAP_CALLS_EXHAUSTED"
    tags = T.verify(parent, key=KEY).tags
    assert (ledger.used(tags[0]), ledger.used(tags[1])) == (2, 100)
    # A fresh sub-token with a larger number does not raise the inherited limit.
    greedy = T.attenuate(parent, T.max_calls(1000), T.max_budget_qb(100000))
    assert _reason(ledger.reserve, greedy, _req(**lead)) == "CAP_CALLS_EXHAUSTED"
    assert all("lead" not in json.dumps(row) and "w1" not in json.dumps(row) for row in ledger.decision_log)


def test_a_refused_request_consumes_nothing():
    ledger = TokenLedger(key=KEY)
    token = T.mint("session", "s", [T.once(NONCE), T.tools("a")], key=KEY, tid=TID)
    assert _reason(ledger.reserve, token, _req(tool="b")) == "CAP_TOOL"
    assert _reason(ledger.reserve, token, _req(session="t")) == "CAP_SCOPE"
    assert _reason(ledger.reserve, token, _req(charge=-1)) == "CAP_REQUEST"
    ledger.commit(ledger.reserve(token, _req()))
    assert _reason(ledger.reserve, token, _req()) == "CAP_USED"


def test_revoking_a_tag_kills_every_token_through_it():
    ledger = TokenLedger(key=KEY)
    root = T.mint("session", "s", key=KEY, tid=TID)
    left = T.attenuate(root, T.tools("a"))
    right = T.attenuate(root, T.tools("b"))
    leaf = T.attenuate(left, T.max_calls(5))
    ledger.revoke(T.verify(left, key=KEY).tags[-1])
    assert _reason(ledger.reserve, left, _req()) == "CAP_REVOKED"
    assert _reason(ledger.reserve, leaf, _req()) == "CAP_REVOKED"
    ledger.commit(ledger.reserve(right, _req(tool="b")))
    ledger.revoke(T.verify(root, key=KEY).root_tag)
    assert _reason(ledger.reserve, right, _req(tool="b")) == "CAP_REVOKED"
    assert _reason(ledger.revoke, "nope") == "CAP_FORMAT"


# Bounds: a parent with calls<=N and budget_qb<=B, a child that adds calls<=1
# and budget_qb<=5, and a sibling that adds only a tool list. Steps are
# (actor, charge in {0, 3, 5}, outcome in {commit, abort, leave open}), 27 in
# all. LIMITS maps (N, B) to the longest schedule enumerated: every schedule
# of 1..3 steps (20,439) for two pairs, 1..2 steps (756) for three more.
# After every step the ledger's decision must equal plain integer counters,
# and committed use under each tag must be within its limit.

LIMITS = {(2, 8): 3, (3, 6): 3, (0, 8): 2, (1, 8): 2, (3, 0): 2}
STEPS = tuple(itertools.product(("parent", "child", "sibling"), (0, 3, 5), ("commit", "abort", "open")))


def _subtree(n_calls, budget):
    parent = T.mint("session", "s", [T.max_calls(n_calls), T.max_budget_qb(budget)], key=KEY, tid=TID)
    tokens = {
        "parent": parent,
        "child": T.attenuate(parent, T.max_calls(1), T.max_budget_qb(5)),
        "sibling": T.attenuate(parent, T.tools("a")),
    }
    p_calls, p_budget = T.verify(parent, key=KEY).tags
    c_calls, c_budget = T.verify(tokens["child"], key=KEY).tags[2:]
    return tokens, (p_calls, p_budget, c_calls, c_budget), {p_calls: n_calls, p_budget: budget, c_calls: 1, c_budget: 5}


def _subtree_schedule(tree, schedule):
    tokens, (p_calls, p_budget, c_calls, c_budget), limits = tree
    ledger = TokenLedger(key=KEY)
    used = dict.fromkeys(limits, 0)
    held = dict.fromkeys(limits, 0)
    admitted = 0
    for actor, charge, outcome in schedule:
        need = {p_calls: 1, p_budget: charge}
        if actor == "child":
            need.update({c_calls: 1, c_budget: charge})
        expect = all(used[tag] + held[tag] + amount <= limits[tag] for tag, amount in need.items())
        try:
            reservation = ledger.reserve(tokens[actor], _req(charge=charge))
        except Denied:
            assert not expect, (schedule, actor)
            continue
        assert expect, (schedule, actor)
        admitted += 1
        if outcome == "commit":
            ledger.commit(reservation)
            for tag, amount in need.items():
                used[tag] += amount
        elif outcome == "abort":
            ledger.abort(reservation)
        else:
            for tag, amount in need.items():
                held[tag] += amount
        for tag, limit in limits.items():
            assert ledger.used(tag) == used[tag] <= limit, (schedule, actor)
    return admitted


def test_enumeration_a_subtree_never_spends_past_an_inherited_limit():
    schedules = admitted = 0
    for (n_calls, budget), depth in LIMITS.items():
        tree = _subtree(n_calls, budget)
        for length in range(1, depth + 1):
            for schedule in itertools.product(STEPS, repeat=length):
                admitted += _subtree_schedule(tree, schedule)
                schedules += 1
    assert schedules == 2 * (27 + 729 + 19683) + 3 * (27 + 729)
    assert admitted > 0


# --- gateway wiring ----------------------------------------------------------

def test_the_rule_code_is_registered_once():
    assert _V12_CODES[CAPABILITY_TOKEN_DENIED] == -32083
    assert len(set(_V12_CODES.values())) == len(_V12_CODES)
    assert CAPABILITY_TOKEN_DENIED in RULES and CAPABILITY_TOKEN_DENIED in _LOG_KIND_RULES


def _send(engine, key=KEY_A, session="s", **arguments):
    return engine.evaluate_call(key, session, "send_email", {"to": "a@b.c", "body": "hi", **arguments})


def _why(out):
    assert out["allowed"] is False and out["code"] == -32083
    assert out["error"] == "capability_token_denied" and out["rule_code"] == CAPABILITY_TOKEN_DENIED
    return out["capability"]["reason"]


def test_inert_until_attached_then_outbound_calls_need_the_token(engine: PolicyEngine):
    engine._clock = lambda: 1_000.0
    assert _send(engine)["allowed"] and engine.cap_tokens is None
    token = T.mint("session", "s", [T.tools("send_email"), T.arg("send_email", "to", "in", ["a@b.c"]),
                                    T.expires(1_000_500), T.max_calls(2)])
    info = engine.attach_capability_token("s", token)
    assert info["caveats"] == 4 and engine.capability_token_attached("s")
    assert _send(engine)["allowed"]
    assert _why(_send(engine, to="evil@x.y")) == "CAP_ARGUMENT"
    assert _why(engine.evaluate_call(KEY_A, "s", "send_webhook", {"body": "x"})) == "CAP_TOOL"
    # A local read is not an outbound event: not checked, no use consumed.
    assert engine.evaluate_call(KEY_A, "s", "lookup_order_status", {"order_id": 1})["allowed"]
    assert _send(engine)["allowed"]
    assert _why(_send(engine)) == "CAP_CALLS_EXHAUSTED"
    # Another session is untouched. A denial does not freeze the key.
    assert _send(engine, session="other")["allowed"]
    assert engine.registry.is_frozen_key(KEY_A, engine.now()) is False
    assert any(f["kind"] == CAPABILITY_TOKEN_DENIED for f in engine.findings)


def test_expiry_and_single_use(engine: PolicyEngine):
    clock = [1_000.0]
    engine._clock = lambda: clock[0]
    engine.attach_capability_token("s", T.mint("session", "s", [T.expires(1_000_500)]))
    assert _send(engine)["allowed"]
    clock[0] = 1_001.0
    assert _why(_send(engine)) == "CAP_EXPIRED"
    engine.attach_capability_token("u", T.mint("session", "u", [T.once()]))
    assert _send(engine, session="u")["allowed"]
    assert _why(_send(engine, session="u")) == "CAP_USED"


def test_an_attached_token_can_only_be_replaced_by_an_extension(engine: PolicyEngine):
    token = T.mint("session", "s", [T.tools("send_email", "send_webhook")])
    engine.attach_capability_token("s", token)
    assert _reason(engine.attach_capability_token, "s", T.mint("session", "s", [])) == "CAP_WIDEN"
    assert _reason(engine.attach_capability_token, "s",
                   T.mint("session", "s", [T.tools("send_email", "send_webhook")])) == "CAP_WIDEN"
    flipped = token[:-1] + ("0" if token[-1] != "0" else "1")
    assert _reason(engine.attach_capability_token, "s", flipped) == "CAP_SIGNATURE"
    engine.attach_capability_token("s", T.attenuate(token, T.tools("send_email")))
    assert _why(engine.evaluate_call(KEY_A, "s", "send_webhook", {"body": "x"})) == "CAP_TOOL"
    assert _send(engine)["allowed"]
    # A token minted for another session does not admit this one.
    engine.attach_capability_token("t", T.mint("session", "s", []))
    assert _why(_send(engine, session="t")) == "CAP_SCOPE"


def test_a_later_denial_gives_the_use_back(engine: PolicyEngine):
    token = T.mint("session", "s", [T.max_calls(1)])
    engine.attach_capability_token("s", token)
    allow = engine._allow

    def deny(sess, step, tool_name, args, eclass, constrained=False, delegation=None):
        return engine._deny(sess, step, tool_name, args, "ssrf_boundary_violation", -32032)

    engine._allow = deny
    assert _send(engine)["allowed"] is False
    tag = T.verify(token).tags[0]
    assert engine.cap_tokens.used(tag) == 0 and engine.cap_tokens.open == {}
    engine._allow = allow
    assert _send(engine)["allowed"]
    assert engine.cap_tokens.used(tag) == 1 and engine.cap_tokens.open == {}
    assert _why(_send(engine)) == "CAP_CALLS_EXHAUSTED"


def _p3_pair(engine: PolicyEngine):
    manifest = SelectionManifest((("", "read_internal_secrets"), ("", "report_metric")))
    schemas = {
        "read_internal_secrets": FieldSchema("read_internal_secrets", (("unused", Constant()),)),
        "report_metric": FieldSchema("report_metric", (("v", Enum(1 << 12)),)),
    }
    cfg = P3Config(budget_qb=4096, link_sources=frozenset({"control_plane"}))
    for sid in ("lead", "worker"):
        engine.attach_leakage_budget(sid, cfg, manifest=manifest, schemas=schemas)


def test_a_coalition_token_shares_one_quarter_bit_budget_with_p3(engine: PolicyEngine):
    """A sub-token's budget is charged what P3 charges, and a refusal aborts the P3 reservation."""
    engine._clock = lambda: 0.0
    _p3_pair(engine)
    parent = T.mint("coalition", "lead", [T.tools("read_internal_secrets", "report_metric"),
                                         T.max_budget_qb(150)])
    engine.attach_capability_token("lead", parent)
    engine.attach_capability_token("worker", T.attenuate(parent, T.only_session("worker"),
                                                         T.tools("report_metric")))
    # Not linked yet: the worker is outside the anchor's coalition.
    assert _why(engine.evaluate_call(KEY_B, "worker", "report_metric", {"v": 1})) == "CAP_SCOPE"
    engine.p3_link("lead", "worker", "control_plane")
    assert engine.evaluate_call(KEY_A, "lead", "read_internal_secrets", {})["allowed"]      # 16 qb
    assert engine.evaluate_call(KEY_B, "worker", "report_metric", {"v": 1})["allowed"]      # 64 qb
    spent = engine.p3_state("lead")["spent_qb"]
    assert spent == 80
    assert engine.cap_tokens.used(T.verify(parent).tags[1]) == 80
    # 64 more would be 144 qb on a 150 qb token: fine. A second one would be 208.
    assert engine.evaluate_call(KEY_A, "lead", "report_metric", {"v": 2})["allowed"]
    refused = engine.evaluate_call(KEY_B, "worker", "report_metric", {"v": 3})
    assert _why(refused) == "CAP_BUDGET_EXHAUSTED"
    state = engine.p3_state("worker")
    assert state["spent_qb"] == 144 and state["pending"] is None  # P3 was not charged for the refused event
    assert engine.cap_tokens.used(T.verify(parent).tags[1]) == 144
    assert _why(engine.evaluate_call(KEY_B, "worker", "read_internal_secrets", {})) == "CAP_TOOL"
