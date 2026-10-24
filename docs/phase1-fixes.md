# Phase 1 fixes (post Tier-2 evaluation)

Date: 2026-10-23 (America/Los_Angeles)

## 1. R14 `parasitic_session_fork` — single-client false positive

**Problem:** The Phase-1 Playwright BFS crawler fired R14 because a valid human-like beacon (`pointer_trail_seen`) was concurrent with the same client's own unlinked navigations (ARIA, `/kb/`, `/llms.txt`, …) inside the 500 ms window.

**Change (agent-watch):**
- Same-session R14 now requires at least one fork with `cursor_prov == "schema"` concurrent with a human beacon branch. Bare `never_offered` / BFS unlinked jumps from one client never qualify.
- Added `detect_parasitic_across_clients()` for a real second session (same IP, different UA/session): rider probes while a human session browses. Wired through `analyze_sessions` → `score_session(..., extra_findings=…)`.

**Change (rogue-ai-pipeline):**
- `_r14.suspicious()` no longer treats bare unlinked navigations as forks. Schema provenance or the collector's `parasitic_session_fork` signal required.

**Tests:**
- `test_r14_single_client_bfs_unlinked_is_not_a_fork`
- `test_r14_cross_client_two_sessions_on_same_ip`
- `test_phase1_crawler_trace_has_no_r14_after_fix` (archived crawler trace)
- Existing same-session schema rider + `mimic_parasitic_rider` still pass
- Pipeline: `test_r14_bare_unlinked_single_client_is_not_a_fork`; `_rider` updated to schema cursors

**Rescore:** crawler still **critical** (ARIA + inversion + hidden link) and still produces a pipeline lead (**R10, R11** only — **no R14**).

## 2. `kinematic_dwell_ok` for scripted Playwright human

**Problem:** Beacon used only `mousedown`/`mouseup` and a tight non-collinear check; Playwright's pointer events + short paths left `kinematic_dwell_ok=false` even with scripted curved moves and ≥12 ms press.

**Change:**
- Beacon script (`frontier.beacon_script`): listen to `pointerdown`/`pointerup` as well as mouse; track `mousemove` too; `nc()` uses max cross-product over the path (`> 1` px).
- Scripted human harness: stronger curved approach + press dwell 50–140 ms before navigation.
- **Still false by design** for touch, switch-access, keyboard / screen-reader activation (no curved mouse press path).
- **`vlm_quantized_interaction` corroboration unchanged:** still needs full assets + valid proof + ≥ `vlm_min_beacons` with `inertial_scroll_ok=false` AND (`kinematic_dwell_ok=false` OR inversion hit). Making dwell achievable for a careful mouse user does not alone create a VLM label.

**Recheck (2026-10-23 evening, America/Los_Angeles):** scripted `human_control` against loopback honeypot → 2/2 beacons with `kinematic_dwell_ok: true` (and `inertial_scroll_ok: true`).

## Files touched

| path | change |
|---|---|
| `agent-watch/agentwatch/frontierdetect.py` | R14 same-session schema-only; `detect_parasitic_across_clients` |
| `agent-watch/agentwatch/scoring.py` | `extra_findings` / cross-client wiring |
| `agent-watch/agentwatch/frontier.py` | beacon kinematics |
| `agent-watch/tests/test_v6.py` | new R14 tests; rider uses schema cursor |
| `agent-watch/redteam/playwright_agents/run_browser_agent.py` | human mouse/dwell calibration |
| `rogue-ai-pipeline/rogue_pipeline/layer2_rules.py` | R14 suspicious() |
| `rogue-ai-pipeline/tests/test_v6_pipeline.py` | schema rider + bare-unlinked negative |

## Test results (this pass)

- `agent-watch`: `tests/test_v6.py` + `tests/test_real_llm_traces.py` → **64 passed**
- `rogue-ai-pipeline`: R14-related in `tests/test_v6_pipeline.py` → **4 passed**

## 3. Gemini refinements (2026-10-23 evening, America/Los_Angeles)

### R14 interleaved disjoint depth

**Change:** Same-session R14 now requires interleaved depth progression on **two disjoint subtrees**: the human tab advances while a schema-provenance fork with **missing or non-parent Referer** lands on a disjoint first-segment path within the fork window. Same-client BFS fan-out with `Referer: /` stays **negative** (parent-Referer forks are excluded). Cross-client R14 unchanged.

**Tests added/updated:**
- `test_r14_same_client_bfs_with_referer_root_stays_negative` (agent-watch)
- `test_r14_bfs_referer_root_stays_negative` (pipeline)
- `_human_with_rider` / `_rider` / `mimic_parasitic_rider` use disjoint `/api` forks with missing Referer

### `kinematic_dwell_ok` inconclusive for touch / OS tap

**Change:** Beacon `dwellOk()` returns JSON `null` (inconclusive) when dwell &lt; 12 ms and (`pointerType` is touch/pen, or TouchEvent surface, or dwell ≤ 4 ms without webdriver/DOM automation). Mobile and trackpad OS tap-to-click commonly produce **0–4 ms** synthetic mousedown/mouseup pairs. Short dwell *with* automation props remains `false`. Honeytoken accepts `null` for `kinematic_dwell_ok` only.

**VLM corroboration unchanged:** `vlm_quantized_interaction` still needs `kinematic_dwell_ok is False` (null does **not** corroborate) plus bad scroll / inversion.

**Test:** `test_kinematic_dwell_inconclusive_null_does_not_corroborate_vlm`

### Retest (this pass)

- `agent-watch`: `tests/test_v6.py` + `tests/test_real_llm_traces.py` → **66 passed**
- `rogue-ai-pipeline`: R14-related (`r14` + `two_tab_reader`) → **5 passed**
