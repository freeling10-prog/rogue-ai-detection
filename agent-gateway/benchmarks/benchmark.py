"""Reproducible bounded microbenchmarks, not an end-to-end SLA certificate."""
from __future__ import annotations

import gc
from pathlib import Path
import json
import math
import platform
import random
import sys
import time
import tracemalloc

from agent_gateway.common import Denied
from agent_gateway.registry_pin_validator import Registry
from agent_gateway.workspace_path_validator import Node, Snapshot, analyze_shell
from agent_gateway.lattice_flow_validator import Call, Gate, Label, MethodPolicy, Step
from agent_gateway.shingle_similarity_validator import Matcher
from agent_gateway.linear_obligation_validator import (
    ObligationManifest, ObligationNet, TransitionSpec)
from agent_gateway.symbolic_fs_transducer import FsTransducer
from agent_gateway.canonical_argument_confinement import Command, FieldPolicy, Policy, confine
from agent_gateway.fork_join_vector_validator import UNIT, WIDTH, Owner, Root
from agent_gateway.dynamic_ingression_validator import Field, Ingression

N = 5000


def percentile(values, q):
    return sorted(values)[math.ceil(len(values) * q) - 1] / 1e6


def run(name, fn, prepare=None):
    wall = []
    cpu = []
    for _ in range(200):
        if prepare:
            prepare()
        fn()
    for _ in range(N):
        if prepare:
            prepare()  # Explicitly excluded: control-plane setup.
        c0 = time.process_time_ns()
        w0 = time.perf_counter_ns()
        fn()
        wall.append(time.perf_counter_ns() - w0)
        cpu.append(time.process_time_ns() - c0)
    return {"name": name, "samples": N,
            "wall_p50_ms": percentile(wall, .5),
            "wall_p99_ms": percentile(wall, .99),
            "wall_max_ms": max(wall) / 1e6,
            "cpu_p99_ms": percentile(cpu, .99)}


def main():
    r = Registry()
    for i in range(256):
        r.register("provider", f"method{i}",
                   '{"inputSchema":{"type":"object"},"description":"Return a record."}')
    r.seal()
    nodes = {"/ws": Node("dir"), "/ws/out": Node("dir")}
    for i in range(64):
        nodes[f"/ws/out/f{i}"] = Node("file", (1, i + 1))
    snap = Snapshot(nodes)
    shell = "echo x | tee -- " + " ".join(f"out/f{i}" for i in range(64))

    def path_case():
        snap.check_all(analyze_shell(shell))

    holder = {}
    step = Step("s", "p", "write", "pin", (("target", "/ws/out/*"),))
    call = Call("k", "s", "p", "write", "pin", (("target", "/ws/out/f0"),), "args")

    def fresh_gate():
        holder["gate"] = Gate("job", (step,), {("p", "write"): MethodPolicy(True, False)})
        holder["gate"].ingest(Label.EXTERNAL)

    rng = random.Random(17)
    protected = tuple("".join(rng.choices("abcdefghijklmnpqrstuvwxyz", k=256))
                      for _ in range(16))
    query = "".join(rng.choices("ABCDEFGHJKLMNPQRSTUVWXYZ0123", k=256))
    tracemalloc.start()
    matcher = Matcher(b"benchmark-only-key-material-32byte", protected)
    matcher_retained, matcher_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert not matcher.check(query).blocked

    # 16 places, 64 transitions: a resource cleanup place per pair, plus an
    # outbound step that requires every cleanup place to be settled.
    specs = [TransitionSpec("p", "outbound", (1,), (1,), True)]
    for i in range(63):
        place = 1 + i % 15
        specs.append(TransitionSpec("p", f"t{i}", (1,) + (0,) * 15,
                                    tuple(1 if j == place else 0 for j in range(16)), False))
    obligation = ObligationManifest(0x1, 0xFFFF_FFFF_0000_0000, tuple(specs))

    def fresh_net():
        holder["net"] = ObligationNet(obligation)

    # One read source joined into 63 write targets: W's check plus 64 label
    # lookups and a copy-on-write overlay of 63 entries.
    label_intents = analyze_shell("cat out/f0 | tee -- " + " ".join(f"out/f{i}" for i in range(1, 64)))

    def fresh_transducer():
        holder["fs"] = FsTransducer(snap)

    # 16 fields at the 2048-byte wire budget: 8 numbers at scale 6, 4 full
    # 32-element sets in reverse order, 2 texts and 2 booleans at their defaults.
    fields = ([FieldPolicy(f"n{i}", "number", scale=6) for i in range(8)]
              + [FieldPolicy(f"s{i}", "set") for i in range(4)]
              + [FieldPolicy(f"t{i}", "text") for i in range(2)]
              + [FieldPolicy(f"b{i}", "bool", default=b"false") for i in range(2)])
    argument_policy = Policy(tuple(fields))
    members = [f'"n{i}":{rng.randint(-10**8, 10**8)}.{rng.randint(0, 10**9):09d}' for i in range(8)]
    members += [f'"s{i}":[' + ",".join(f'"{chr(97 + i)}{j:02d}"' for j in reversed(range(32))) + "]"
                for i in range(4)]
    members += ['"b0":false', '"b1":false']
    rng.shuffle(members)
    body = "{" + ",".join(members) + ',"t0":"","t1":""}'
    pad = 2048 - len(body.encode())
    wire = body.replace('"t0":""', '"t0":"' + "x" * pad + '"').encode()
    assert len(wire) == 2048
    canonical = argument_policy.canonicalize(wire)
    assert argument_policy.canonicalize(canonical) == canonical
    command = Command("chmod", tuple(f"out/f{i}" for i in range(16)), mode="0644")

    # A full-width ledger: the root and 7 forked branches, each holding a share of
    # every budget. One batch fires a weighted transition and sends, which scans
    # cleanup state across all 8 branches x 16 places (place 15, empty everywhere,
    # so the scan never stops early).
    ledger = Root.make(denials=64, outbound=65535, tokens=(8 * UNIT,) * 15 + (0,),
                       obligation_mask=0x8000)
    for _ in range(WIDTH - 1):
        share = (8, 8000) + (UNIT,) * 15 + (0,)
        ledger, _ = ledger.fork(0, ledger.branches[0].clock[0], share)
    fire = ((UNIT,) + (0,) * 15, (0, UNIT) + (0,) * 14)
    batch = [("fire", *fire), ("send", 512)]

    def fresh_owner():
        holder["owner"] = Owner(ledger)

    # Inbound: 32 fields, 4096 bytes in all, each one 128-byte token run that
    # passes the length gate, so every run gets the full entropy count, and none
    # is enrolled (16 distinct values, too many repeats).
    low = "".join(rng.choices("abcdefghijklmnop", k=128))
    response = [Field(low) for _ in range(32)]
    assert sum(len(f.value) for f in response) == 4096
    # Outbound: 8 enrolled 128-byte values against a 512-byte miss.
    pins = Ingression()
    pins.receive([Field("".join(rng.choices("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789", k=128)), sensitive=True)
                  for _ in range(8)])
    miss = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz ", k=512)).encode()
    pins.outbound(miss)

    def fresh_ingression():
        holder["ingress"] = Ingression()

    results = [
        run("registry: qualified lookup, 256 pins", lambda: r.lookup("method255", "provider")),
        run("path: parse + snapshot validation, 64 writes", path_case),
        run("flow: fresh EXTERNAL step admission", lambda: holder["gate"].begin(call), fresh_gate),
        run("similarity: 16 x 256, 256-char miss, both modes", lambda: matcher.check(query)),
        run("obligation: outbound transition, 16 places x 64 transitions",
            lambda: holder["net"].fire("p", "outbound"), fresh_net),
        run("transducer: 1 read joined into 63 writes, copy-on-write overlay",
            lambda: holder["fs"].apply(label_intents), fresh_transducer),
        run("arguments: canonicalize 16 fields, 2048-byte wire", lambda: argument_policy.canonicalize(wire)),
        run("command: confine 16 operands", lambda: confine(command)),
        run("ledger: fire + send batch, 8 branches x 16 places",
            lambda: holder["owner"].apply(0, holder["owner"].clock(0), batch), fresh_owner),
        run("ingress: scan 32 fields, 4096-byte response",
            lambda: holder["ingress"].receive(response), fresh_ingression),
        run("ingress: 512-byte query vs 8 x 128-byte pins", lambda: pins.outbound(miss)),
    ]

    def combined():
        r.lookup("method255", "provider")
        path_case()
        holder["gate"].begin(call)
        matcher.check(query)

    results.append(run("combined: four bounded checks", combined, fresh_gate))

    def prepare_five():
        fresh_gate()
        fresh_net()

    def combined_five():
        combined()
        holder["net"].fire("p", "outbound")

    results.append(run("combined: five bounded checks (with obligation)", combined_five, prepare_five))

    def prepare_six():
        prepare_five()
        fresh_transducer()

    def combined_six():
        combined_five()
        holder["fs"].apply(label_intents)

    results.append(run("combined: six bounded checks (with transducer)", combined_six, prepare_six))

    def combined_seven():
        argument_policy.canonicalize(wire)
        combined_six()

    results.append(run("combined: seven bounded checks (with canonicalization)", combined_seven, prepare_six))

    def prepare_eight():
        prepare_six()
        fresh_owner()

    def combined_eight():
        combined_seven()
        holder["owner"].apply(0, holder["owner"].clock(0), batch)

    results.append(run("combined: eight bounded checks (with fork/join ledger)", combined_eight, prepare_eight))

    def combined_nine():
        combined_eight()
        pins.outbound(miss)

    results.append(run("combined: nine bounded checks (with ingression outbound)", combined_nine, prepare_eight))
    output = {
        "python": sys.version, "platform": platform.platform(),
        "gc_enabled": gc.isenabled(), "samples_per_case": N,
        "matcher_tracemalloc_retained_bytes": matcher_retained,
        "matcher_tracemalloc_peak_bytes": matcher_peak,
        "methodology": (
            "Sequential warm-process microbenchmark; deterministic synthetic inputs; "
            "wall and process CPU clocks; setup excluded; GC left enabled. Path uses "
            "a trusted in-memory model. No filesystem I/O, network, durable commit, "
            "cross-process lock contention, or distributed failover is measured."),
        "results": results}
    out_path = Path(__file__).resolve().with_name("artifacts") / "benchmark_results.json"
    with open(out_path, "w", encoding="utf-8") as stream:
        json.dump(output, stream, indent=2)
        stream.write("\n")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
