#!/usr/bin/env bash
# =====================================================================================================================
# sync_and_score.sh - Zone B "pull, score, anchor" workflow for rogue-ai-pipeline.   DEFENSIVE USE ONLY.
#
# TWO-ZONE MODEL
#   Zone A  A sacrificial, isolated host that runs the agent-watch honeypot and collects hostile traffic. It is assumed to
#           be compromisable. It holds NO credentials for Zone B or anything else and cannot open connections to Zone B.
#   Zone B  The analysis host (this script). It PULLS Zone A's exported logs/leads one-way, scores them with agent-watch and
#           this pipeline, and keeps the audit log, baseline, HMAC secret and STIX output. Zone A never sees any of that.
#   Data crossing A -> B is untrusted. Captured agent text is attacker-controlled: this script never executes or
#   interpolates it, and the pipeline sanitizes it again at ingest.
#
# WHAT THIS SCRIPT DOES (in order)
#   1. rsync PULL from Zone A into a local spool (read-only on A, never --delete, never pushes anything back to A)
#   2. python -m agentwatch analyze   on the pulled logs (+ honeypot leads)
#   3. python -m agentwatch export-leads  -> RawEvent JSONL (+ coordination-event JSONL)
#   4. verify the existing audit log against the last off-host anchor (detects tampering/truncation since last run)
#   5. run.py detect --production --baseline <saved baseline>   (leads are for HUMAN REVIEW; nothing is blocked)
#   6. verify the audit log again
#   7. export STIX 2.1 for HUMAN-CONFIRMED leads only (ids listed by a reviewer in $CONFIRMED_LEADS_FILE; never automatic)
#   8. store the audit head-hash anchor locally AND off-host (separate append-only host)
#
# CONFIGURATION: environment variables only. Nothing host- or key-specific is hard-coded.
#   Required (non-dry-run):
#     ZONE_A_HOST            host name/IP of the Zone A collector
#     ZONE_A_USER            unprivileged account on Zone A used ONLY for this pull
#     ZONE_A_SSH_KEY         path to the private key dedicated to this pull (permissions 0600)
#     ZONE_A_KNOWN_HOSTS     known_hosts file pinning Zone A's host key (host key checking is always strict)
#     ZONE_A_EXPORT_DIR      remote directory to pull (read-only export area), e.g. /var/lib/agent-watch/export
#     WORKDIR                local working directory on Zone B
#     PIPELINE_BASELINE      saved frozen baseline from `run.py train-baseline`
#     PIPELINE_HMAC_SECRET   strong secret for pseudonymization (>= 32 bytes; the pipeline refuses weak/default values)
#     ANCHOR_SSH_DEST        user@host of the OFF-HOST anchor store (a different machine from Zone A and B)
#     ANCHOR_SSH_KEY         key for the anchor store (should be restricted to appending to one file, see below)
#     ANCHOR_REMOTE_FILE     file on the anchor host that receives one line per run
#   Optional:
#     PIPELINE_EXPECT_BASELINE_SHA256  refuse the baseline unless its content hash equals this (recommended)
#     PIPELINE_POLICY / PIPELINE_CONFIG / PIPELINE_IDENTITY_REGISTRY   passed to run.py detect when set
#     PIPELINE_PYTHON (default python3)   AGENTWATCH_CONFIG
#     AGENTWATCH_PYTHON      interpreter that can `import agentwatch` (default = PIPELINE_PYTHON); put agent-watch on its
#                            path (pip install, or PYTHONPATH exported by the caller)
#     CONFIRMED_LEADS_FILE   one lead id per line, written by a human reviewer (default $WORKDIR/confirmed_leads.txt)
#     SYNC_MODE              ignore-existing (default) | append   (see "rsync flags")
#     SYNTHETIC_DATA=1       label ingested events synthetic (sandbox/test traffic ONLY). Real traffic additionally needs a
#                            PIPELINE_CONFIG with normalization.require_synthetic = false - a deliberate operator decision.
#
# USAGE
#   deploy/sync_and_score.sh --dry-run     print every step and command; touch nothing (no network, no files, no secrets)
#   deploy/sync_and_score.sh               run for real
#   deploy/sync_and_score.sh --help
#
# SSH KEY RESTRICTIONS (set these up on Zone A; this script cannot enforce them for you)
#   In ~ZONE_A_USER/.ssh/authorized_keys on Zone A, the pull key should look like one line:
#     restrict,from="<Zone B address>",command="rrsync -ro /var/lib/agent-watch/export" ssh-ed25519 AAAA... zone-b-pull
#   * restrict            disables pty, port/agent/X11 forwarding and ~/.ssh/rc
#   * from="..."          only Zone B's address may use the key
#   * command=rrsync -ro  forces the read-only rsync wrapper rooted at the export dir: the key cannot list other paths,
#                         cannot write, cannot get a shell, even if Zone B were compromised or the key leaked
#   * the Zone A user owns nothing but the export directory; Zone A's firewall allows inbound SSH from Zone B only and
#     NO outbound connections to Zone B.  The private key lives only on Zone B (never on A, never in an agent forwarder).
#   Anchor store: use a different key limited to appending, e.g.
#     restrict,command="cat >> /var/anchors/rogue-pipeline.log" ssh-ed25519 AAAA... anchor-writer
#   (this script then supplies only the line; the forced command decides where it goes).
#
# rsync FLAGS (pull only; the local path is always the destination)
#   -rt                 recurse, keep mtimes. No -a: ownership/permissions/devices/symlinks from Zone A are not reproduced.
#   --safe-links        ignore symlinks that point outside the tree (a hostile Zone A cannot plant links to Zone B files)
#   --max-size=100M     bound what a hostile Zone A can make us store;   --timeout=120  bound hangs
#   --no-perms --no-owner --no-group --chmod=F0640,D0750   files land with fixed local modes
#   SYNC_MODE=ignore-existing (default): --ignore-existing  files already in the spool are NEVER overwritten, so a
#                         compromised Zone A cannot rewrite history we already hold. Requires Zone A to rotate logs into new
#                         immutable files (e.g. leads-<date>.jsonl).
#   SYNC_MODE=append:     --append-verify  for logs that grow in place: only bytes after the local length are fetched, and the
#                         common prefix is checksum-verified first (a mismatch makes rsync re-send the file in full - review
#                         the audit trail if that ever happens).
#   Never used: --delete, --remove-source-files, or any destination other than the local spool.
# =====================================================================================================================
set -euo pipefail

DRY_RUN=0
case "${1:-}" in
  --dry-run) DRY_RUN=1 ;;
  -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
  "") ;;
  *) echo "usage: $0 [--dry-run|--help]" >&2; exit 64 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PIPELINE_PYTHON="${PIPELINE_PYTHON:-python3}"
AGENTWATCH_PYTHON="${AGENTWATCH_PYTHON:-$PIPELINE_PYTHON}"
SYNC_MODE="${SYNC_MODE:-ignore-existing}"

log() { printf '[sync_and_score %s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
die() { printf '[sync_and_score] ERROR: %s\n' "$*" >&2; exit 1; }

# run <cmd...>: execute, or just print in dry-run mode. Nothing is ever passed through eval or a shell string.
run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] would run:'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

# req VAR: required environment variable (reported but not fatal in dry-run mode). Never prints values.
req() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then log "dry-run: $name is not set (a real run would stop here)"; return 0; fi
    die "required environment variable $name is not set"
  fi
}

for v in ZONE_A_HOST ZONE_A_USER ZONE_A_SSH_KEY ZONE_A_KNOWN_HOSTS ZONE_A_EXPORT_DIR WORKDIR PIPELINE_BASELINE \
         PIPELINE_HMAC_SECRET ANCHOR_SSH_DEST ANCHOR_SSH_KEY ANCHOR_REMOTE_FILE; do req "$v"; done
case "$SYNC_MODE" in ignore-existing|append) ;; *) die "SYNC_MODE must be ignore-existing or append" ;; esac

WORKDIR="${WORKDIR:-/nonexistent-workdir-dry-run}"
SPOOL="$WORKDIR/spool"
BATCH_ID="$(date -u +%Y%m%dT%H%M%SZ)"
BATCH="$WORKDIR/batches/$BATCH_ID"
STATE="$WORKDIR/state"                   # persistent audit log lives here (append-only across runs)
ANCHORS="$WORKDIR/anchors"
CONFIRMED_LEADS_FILE="${CONFIRMED_LEADS_FILE:-$WORKDIR/confirmed_leads.txt}"

if [ "$DRY_RUN" -eq 1 ]; then
  log "DRY RUN: nothing will be created, read, transferred or executed. Batch id would be $BATCH_ID."
else
  for tool in rsync ssh flock "$PIPELINE_PYTHON" "$AGENTWATCH_PYTHON"; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
  done
  [ -r "$ZONE_A_SSH_KEY" ] || die "ZONE_A_SSH_KEY is not readable"
  [ -r "$ZONE_A_KNOWN_HOSTS" ] || die "ZONE_A_KNOWN_HOSTS is not readable (host key must be pinned)"
  [ -r "$PIPELINE_BASELINE" ] || die "PIPELINE_BASELINE is not readable (train one with: run.py train-baseline)"
fi

# --- 0. production mode + lock ----------------------------------------------------------------------------------------
export PIPELINE_ENV=production            # the pipeline then REQUIRES a strong PIPELINE_HMAC_SECRET and refuses fallbacks
unset ROGUE_PIPELINE_HMAC_KEY || true     # the dev key must never leak into a production run (it would be ignored anyway)
if [ "$DRY_RUN" -eq 0 ]; then
  mkdir -p "$SPOOL" "$BATCH" "$STATE" "$ANCHORS"
  chmod 700 "$WORKDIR" "$STATE" "$ANCHORS"
  exec 9>"$WORKDIR/.lock"
  flock -n 9 || die "another run holds $WORKDIR/.lock"
else
  log "dry-run: would create $SPOOL $BATCH $STATE $ANCHORS and take a flock on $WORKDIR/.lock"
fi

# --- 1. one-way pull from Zone A ----------------------------------------------------------------------------------------
log "step 1/8: pull from Zone A (read-only; mode=$SYNC_MODE)"
SSH_CMD="ssh -i ${ZONE_A_SSH_KEY:-<key>} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${ZONE_A_KNOWN_HOSTS:-<known_hosts>} -o ForwardAgent=no -o ForwardX11=no -o ConnectTimeout=20"
RSYNC_ARGS=(-rt --safe-links --max-size=100M --timeout=120 --no-perms --no-owner --no-group "--chmod=F0640,D0750")
if [ "$SYNC_MODE" = "append" ]; then RSYNC_ARGS+=(--append-verify); else RSYNC_ARGS+=(--ignore-existing); fi
run rsync "${RSYNC_ARGS[@]}" -e "$SSH_CMD" "${ZONE_A_USER:-<user>}@${ZONE_A_HOST:-<host>}:${ZONE_A_EXPORT_DIR:-<dir>}/" "$SPOOL/"

# --- 2. agent-watch analyze --------------------------------------------------------------------------------------------
log "step 2/8: python -m agentwatch analyze"
shopt -s nullglob
LOGS=("$SPOOL"/logs/*)
LEADS=("$SPOOL"/leads/*.jsonl)
if [ "$DRY_RUN" -eq 1 ]; then LOGS=("$SPOOL/logs/<pulled logs>"); LEADS=("$SPOOL/leads/<pulled leads>.jsonl"); fi
AW_ARGS=(-m agentwatch analyze)
[ -n "${AGENTWATCH_CONFIG:-}" ] && AW_ARGS+=(--config "$AGENTWATCH_CONFIG")
if [ "${#LOGS[@]}" -gt 0 ]; then
  run "$AGENTWATCH_PYTHON" "${AW_ARGS[@]}" "${LOGS[@]}" --leads "${LEADS[@]}" --json-out "$BATCH/agentwatch-report.json" --no-color
else
  log "no access/gateway logs pulled; skipping analyze (honeypot leads are still exported below)"
fi

# --- 3. export leads -> RawEvent (+ coordination events) ------------------------------------------------------------------
log "step 3/8: export-leads -> RawEvent JSONL"
EXPORT_FLAGS=()
[ "${SYNTHETIC_DATA:-0}" = "1" ] && EXPORT_FLAGS+=(--label-synthetic)
COORD_FILES=()
i=0
for lf in "${LEADS[@]}"; do
  i=$((i + 1))
  run "$AGENTWATCH_PYTHON" -m agentwatch export-leads "$lf" --out "$BATCH/raw-$i.jsonl" --coordination-out "$BATCH/coord-$i.jsonl" "${EXPORT_FLAGS[@]}"
  COORD_FILES+=("$BATCH/coord-$i.jsonl")
done
if [ "$DRY_RUN" -eq 1 ]; then
  log "dry-run: would concatenate $BATCH/raw-*.jsonl into $BATCH/events.jsonl"
else
  cat "$BATCH"/raw-*.jsonl > "$BATCH/events.jsonl" 2>/dev/null || : > "$BATCH/events.jsonl"
fi

# --- 4. verify the audit log against the last off-host anchor (BEFORE adding to it) ----------------------------------------------
AUDIT="$STATE/audit.jsonl"
log "step 4/8: verify existing audit log against the last anchor"
if [ "$DRY_RUN" -eq 1 ]; then
  log "dry-run: would run: run.py verify-log --log $AUDIT --anchor <contents of $ANCHORS/last_head, if present>"
elif [ -s "$AUDIT" ]; then
  [ -s "$ANCHORS/last_head" ] || die "audit log exists but there is no local anchor file; restore the last anchor from the off-host store"
  "$PIPELINE_PYTHON" "$PIPELINE_ROOT/run.py" verify-log --log "$AUDIT" --anchor "$(cat "$ANCHORS/last_head")" \
    || die "AUDIT LOG FAILED VERIFICATION against the last anchor: stop and investigate (possible tampering)"
else
  log "no audit log yet (first run)"
fi

# --- 5. detect (production mode, frozen baseline) -------------------------------------------------------------------------------
log "step 5/8: run.py detect --production --baseline"
DET=(detect --production --events "$BATCH/events.jsonl" --baseline "${PIPELINE_BASELINE:-<baseline>}" --out "$STATE" --append-log)
[ -n "${PIPELINE_EXPECT_BASELINE_SHA256:-}" ] && DET+=(--expect-baseline-sha256 "$PIPELINE_EXPECT_BASELINE_SHA256")
[ -n "${PIPELINE_POLICY:-}" ] && DET+=(--policy "$PIPELINE_POLICY")
[ -n "${PIPELINE_CONFIG:-}" ] && DET+=(--config "$PIPELINE_CONFIG")
[ -n "${PIPELINE_IDENTITY_REGISTRY:-}" ] && DET+=(--identity-registry "$PIPELINE_IDENTITY_REGISTRY")
[ "${SYNTHETIC_DATA:-0}" = "1" ] && DET+=(--label-synthetic)
if [ "${#COORD_FILES[@]}" -gt 0 ]; then DET+=(--coordination "${COORD_FILES[@]}"); fi
# PIPELINE_HMAC_SECRET is inherited from the environment; it is never put on a command line.
run "$PIPELINE_PYTHON" "$PIPELINE_ROOT/run.py" "${DET[@]}"
if [ "$DRY_RUN" -eq 0 ]; then
  cp "$STATE/leads.json" "$BATCH/leads.json"; cp "$STATE/leads.md" "$BATCH/leads.md"   # keep this batch's leads with the batch
fi

# --- 6. verify again, capture the new head ----------------------------------------------------------------------------------------
log "step 6/8: verify audit log after the run"
if [ "$DRY_RUN" -eq 1 ]; then
  log "dry-run: would run: run.py verify-log --log $AUDIT   and read the new head hash"
  HEAD="<new head hash>"
else
  OUT="$("$PIPELINE_PYTHON" "$PIPELINE_ROOT/run.py" verify-log --log "$AUDIT")" || die "audit log failed verification after the run"
  echo "$OUT"
  HEAD="$(printf '%s\n' "$OUT" | grep -Eo '[0-9a-f]{64}' | tail -n 1)"
  [ -n "$HEAD" ] || die "could not read the audit head hash"
fi

# --- 7. STIX for HUMAN-CONFIRMED leads only ----------------------------------------------------------------------------------------
log "step 7/8: STIX 2.1 export for confirmed leads only"
if [ "$DRY_RUN" -eq 1 ]; then
  log "dry-run: would read lead ids from $CONFIRMED_LEADS_FILE and run: run.py export-stix --leads $BATCH/leads.json --confirm <ids> --out $BATCH/confirmed.stix.json"
elif [ -s "$CONFIRMED_LEADS_FILE" ]; then
  mapfile -t CONFIRMED < <(grep -E '^lead-[0-9a-f]{12}$' "$CONFIRMED_LEADS_FILE" || true)
  if [ "${#CONFIRMED[@]}" -gt 0 ]; then
    "$PIPELINE_PYTHON" "$PIPELINE_ROOT/run.py" export-stix --leads "$BATCH/leads.json" --confirm "${CONFIRMED[@]}" --out "$BATCH/confirmed.stix.json" \
      || log "WARNING: STIX export failed (e.g. a confirmed id is not among this batch's leads); nothing was published"
  else
    log "no valid lead ids in $CONFIRMED_LEADS_FILE: no STIX bundle written"
  fi
else
  log "no confirmed leads file: no STIX bundle written (a human must confirm leads first; nothing is auto-confirmed)"
fi

# --- 8. store the audit head anchor locally and off-host ------------------------------------------------------------------------
log "step 8/8: store audit head anchor off-host"
LINE="$BATCH_ID $HEAD"
if [ "$DRY_RUN" -eq 1 ]; then
  log "dry-run: would write $ANCHORS/last_head and append '$LINE' to ${ANCHOR_SSH_DEST:-<anchor host>}:${ANCHOR_REMOTE_FILE:-<file>} via ssh"
else
  printf '%s\n' "$HEAD" > "$ANCHORS/last_head"
  printf '%s\n' "$LINE" >> "$ANCHORS/history.log"
  # The remote side should have a forced command (see header) so this key can only append one line to one file.
  printf '%s\n' "$LINE" | ssh -i "$ANCHOR_SSH_KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ForwardAgent=no -o ConnectTimeout=20 \
      "$ANCHOR_SSH_DEST" "cat >> '$ANCHOR_REMOTE_FILE'" \
    || die "could not store the anchor off-host. The local anchor is saved; the run is NOT considered anchored until this succeeds"
fi

log "done. Leads are for human review only; nothing was blocked or changed on any host."
