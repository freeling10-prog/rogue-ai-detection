"""Verified identity (simulated HTTP Message Signatures) and IP/ASN allowlists, applied per event BEFORE scoring.

Partner integrations stop tripping the exemptable rules (R3/R4) only when verified; spoof attempts stay scored.
Offline and simulated: HMAC-SHA256 over an RFC 9421-shaped signature base, key from a local registry."""
import json

import pytest

from rogue_pipeline.config import Config, IdentityCfg, IpAllow, AsnAllow, ResolvedPolicy
from rogue_pipeline.features import group_events
from rogue_pipeline.identity import IdentityEntry, IdentityGate, IdentityRegistry, RegistryError, sign_event, signature_base
from rogue_pipeline.layer2_rules import RuleEngine
from rogue_pipeline.normalize import Normalizer
from rogue_pipeline.pseudonymize import Pseudonymizer
from rogue_pipeline.schema import RawEvent

from conftest import KEY, raw
from test_layer2_rules import baseline, LATE, T

P = Pseudonymizer(KEY)
GOOD_KEY = b"partner-key-0123456789abcdef-aaaa"
BAD_KEY = b"attacker-guess-0123456789abcdef-b"
SUFFIX = ".acme-partner.example.net"
DEST = f"api{SUFFIX}"


def registry(agents=(), suffixes=(SUFFIX,), exempt=("R3", "R4")):
    return IdentityRegistry([IdentityEntry("acme-2026", GOOD_KEY, "acme", frozenset(agents), tuple(suffixes), frozenset(exempt))])


def partner_post(i, ts=LATE, key=GOOD_KEY, dest=DEST, signed=True, created=None, **kw):
    ev = raw(i, ts, "a", "tool_call", tool="http_post", resource="/v2/sync", dest_host=dest, payload_bytes=20000, **kw)
    return sign_event(ev, "acme-2026", key, created) if signed else ev


def analyse(evs, reg=None, idcfg=None):
    cfg = Config(identity=idcfg or IdentityCfg())
    rep = Normalizer(cfg.normalization, P, IdentityGate(cfg.identity, reg)).process(evs)
    assert not rep.quarantined, rep.quarantined
    g = group_events(rep.events)
    eng = RuleEngine(cfg.layer2, cfg.tools, ResolvedPolicy())
    return eng.evaluate(g), rep, eng


def r3(flags):
    return [f for f in flags if f.rule_id == "R3"]


def test_unsigned_partner_traffic_trips_r3_control():
    flags, rep, _ = analyse(baseline() + [partner_post(100, signed=False)], registry())
    assert r3(flags) and rep.identity_counts.get("absent", 0) > 0


def test_verified_partner_integration_no_longer_trips_r3():
    flags, rep, eng = analyse(baseline() + [partner_post(100)], registry())
    assert not r3(flags) and rep.identity_counts["verified"] == 1
    assert eng.exempted.get("R3") == 1                                                  # reported, never silent


def test_spoofed_signature_with_wrong_key_is_still_scored_and_marked_failed():
    flags, rep, _ = analyse(baseline() + [partner_post(100, key=BAD_KEY)], registry())
    assert r3(flags) and rep.identity_counts["failed"] == 1 and rep.identity_counts.get("verified", 0) == 0


def test_unknown_keyid_unbound_agent_and_stale_signature_all_fail():
    unknown = sign_event(raw(100, LATE, "a", "tool_call", tool="http_post", dest_host=DEST, payload_bytes=20000), "who-dis", GOOD_KEY)
    assert r3(analyse(baseline() + [unknown], registry())[0])
    bound = registry(agents=["partner-bot"])                                              # key is bound to another agent id
    assert r3(analyse(baseline() + [partner_post(100)], bound)[0])
    assert r3(analyse(baseline() + [partner_post(100, created=int(LATE) - 3600)], registry())[0])       # replayed/stale: outside max_skew_s


def test_tampered_event_fields_invalidate_the_signature():
    ev = partner_post(100)
    ev["dest_host"] = "drop-1.example.org"                                                # changed after signing
    flags, rep, _ = analyse(baseline() + [ev], registry())
    assert r3(flags) and rep.identity_counts["failed"] == 1


def test_verified_identity_is_not_blanket_trust_destination_must_be_in_the_entry_allow_list():
    off = partner_post(100, dest="drop-1.example.org")
    flags, rep, _ = analyse(baseline() + [off], registry())
    assert r3(flags) and rep.identity_counts["verified"] == 1                              # verified, but exemption does not apply there


def test_exemption_is_per_event_a_spoofer_cannot_hide_behind_a_verified_stream():
    evs = baseline() + [partner_post(100), partner_post(101, ts=LATE + 30, signed=False, dest=DEST)]
    flags, _, eng = analyse(evs, registry())
    (f,) = r3(flags)
    assert [e.event_id for e in f.evidence] == ["ev101"]                                   # only the unsigned event is evidence
    assert eng.exempted["R3"] == 1


def test_only_listed_rules_are_exempted():
    flags, _, _ = analyse(baseline() + [partner_post(100)], registry(exempt=("R4",)))
    assert r3(flags)                                                                       # R3 not in this entry's exempt list


def test_ip_allowlist_exempts_only_inside_the_range_and_a_failed_signature_vetoes_it():
    idcfg = IdentityCfg(ip_allowlist=[IpAllow(cidr="198.51.100.0/24", label="acme-egress", allow_dest_suffixes=[SUFFIX])])
    inside = partner_post(100, signed=False, ip="198.51.100.20")
    outside = partner_post(100, signed=False, ip="198.51.101.20")                          # the next /24
    assert not r3(analyse(baseline() + [inside], None, idcfg)[0])
    assert r3(analyse(baseline() + [outside], None, idcfg)[0])
    assert r3(analyse(baseline() + [partner_post(100, key=BAD_KEY, ip="198.51.100.20")], registry(), idcfg)[0])   # bad signature beats the IP list
    off_dest = partner_post(100, signed=False, ip="198.51.100.20", dest="drop-1.example.org")
    assert r3(analyse(baseline() + [off_dest], None, idcfg)[0])                            # allow-list is destination-scoped too


def test_asn_allowlist():
    idcfg = IdentityCfg(asn_allowlist=[AsnAllow(asn=64496, label="acme-asn", allow_dest_suffixes=[SUFFIX])])
    assert not r3(analyse(baseline() + [partner_post(100, signed=False, asn=64496)], None, idcfg)[0])
    assert r3(analyse(baseline() + [partner_post(100, signed=False, asn=64511)], None, idcfg)[0])
    assert r3(analyse(baseline() + [partner_post(100, signed=False)], None, idcfg)[0])


def test_identity_can_be_disabled_and_is_off_without_registry_or_lists():
    flags, rep, _ = analyse(baseline() + [partner_post(100)], registry(), IdentityCfg(enabled=False))
    assert r3(flags) and set(rep.identity_counts) <= {"absent"}
    assert not IdentityGate(IdentityCfg(), None).active


def test_exempted_events_still_reach_the_other_layers():
    flags, rep, _ = analyse(baseline() + [partner_post(100)], registry())
    ev = next(e for e in rep.events if e.event_id == "ev100")
    assert ev.identity == "verified" and "R3" in ev.exempt_rules                          # visible to Layers 1 and 3 and the audit trail


def test_signature_base_and_schema_shape():
    base = signature_base("read", "/x", "h.example", 1700000000, "k")
    assert b'"@method": read' in base and b'alg="hmac-sha256"' in base and b'keyid="k"' in base
    ev = RawEvent(**partner_post(1))
    assert ev.signature.keyid == "acme-2026" and len(ev.signature.value) == 64
    with pytest.raises(Exception):
        RawEvent(**{**partner_post(1), "signature": {"keyid": "k", "created": 1, "value": "zz"}})      # malformed signature is quarantined input


def test_registry_loads_keys_from_environment_and_fails_closed(tmp_path):
    f = tmp_path / "registry.json"
    f.write_text(json.dumps({"keys": [{"keyid": "acme-2026", "key_env": "PARTNER_ACME_KEY", "operator": "acme",
                                       "allow_dest_suffixes": [SUFFIX]}]}))
    with pytest.raises(RegistryError, match="PARTNER_ACME_KEY"):
        IdentityRegistry.from_file(f, env={})                                              # missing key material: refuse, do not skip
    with pytest.raises(RegistryError):
        IdentityRegistry.from_file(f, env={"PARTNER_ACME_KEY": "short"})
    reg = IdentityRegistry.from_file(f, env={"PARTNER_ACME_KEY": GOOD_KEY.decode()})
    assert reg.get("acme-2026").operator == "acme" and "PARTNER_ACME" not in repr(reg) and GOOD_KEY.decode() not in repr(reg)
    flags, _, _ = analyse(baseline() + [partner_post(100)], reg)
    assert not r3(flags)
    f.write_text(json.dumps({"keys": [{"keyid": "k", "key_env": "X", "operator": "o", "surprise": 1}]}))
    with pytest.raises(Exception):
        IdentityRegistry.from_file(f, env={"X": GOOD_KEY.decode()})                        # strict schema: unknown keys rejected


def test_end_to_end_on_simulated_partners_and_spoofers(ext_run, ext_run_noid):
    res, inv = ext_run
    noid, _ = ext_run_noid
    flagged = lambda r: {inv[f.agent] for f in r.flags if f.rule_id in ("R3", "R4") and f.agent in inv}
    partners = {a for a in inv.values() if a.startswith(("pv-", "pip-"))}
    spoofers = {a for a in inv.values() if a.startswith("spoof-")}
    assert partners and len(flagged(noid) & partners) >= len(partners) - 1                  # partners trip without identity
    assert not (flagged(res) & partners)                                                   # ... and stop tripping with it
    assert len(flagged(res) & spoofers) >= 2                                               # spoofers stay scored
    assert res.exempted.get("R3", 0) > 0
