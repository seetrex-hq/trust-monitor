#!/usr/bin/env bash
# Trust Center external monitor — orchestrator.
#
# Fetches everything ONCE per resource (headers and body from the SAME response)
# inside one window, runs the checks, and updates state. Exits non-zero if any
# check failed; the workflow turns that into /fail + no ping.
#
# NEVER `set -x` / `curl -v`: logs are public and the ping URL is a capability
# to silence the alarm.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
. "$HERE/../lib/checks.sh"

: "${TENANT_URL:?}" ; : "${ANCHOR_URL:?}" ; : "${LEGACY_ANCHOR_URL:?}"
: "${LANDING_URL:?}" ; : "${TENANT_SLUG:?}" ; : "${SCHEMA_VERSION:?}"
: "${VERIFIER_BIN:?}" ; : "${BUNDLE_URL:?}"
BUNDLE_VERSION="${BUNDLE_VERSION:-seetrex/anchor-monitor/v1}"
MAX_BUNDLE_AGE_MIN="${MAX_BUNDLE_AGE_MIN:-180}"
MIN_BUNDLE_AGE_MIN="${MIN_BUNDLE_AGE_MIN:--5}"
MAX_STALENESS_MIN="${MAX_STALENESS_MIN:-90}"
MIN_STALENESS_MIN="${MIN_STALENESS_MIN:--5}"
EVIDENCE_MAX_DAYS="${EVIDENCE_MAX_DAYS:-30}"
CERT_MIN_DAYS="${CERT_MIN_DAYS:-14}"
FLAP_WINDOW="${FLAP_WINDOW:-6}"
FLAP_THRESHOLD="${FLAP_THRESHOLD:-2}"

STATE="$ROOT/state"; mkdir -p "$STATE"
HISTORY="$STATE/history.jsonl"; BASELINE="$STATE/baseline.json"
BUNDLE_BASELINE="$STATE/bundle_baseline.json"
DISPUTED="$STATE/disputed.json"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
RETRIED=false; RESULTS=""; RC=0

note() { RESULTS="$RESULTS$1"$'\n'; echo "$1"; }
run()  { local out; out=$("$@" 2>&1); local rc=$?; note "$out"; [ $rc -ne 0 ] && RC=1; return 0; }

# --- reference time: the SCHEDULED slot, not now ------------------------------
# The grid is :20/:50 — both the native cron and the external waker use it.
# `created_at` is when the run was QUEUED, and on a delayed scheduler that is
# NOT the scheduled moment (measured 24 min late on 2026-07-21): labeling it
# "scheduled" let platform delay contaminate C3 through the back door. The slot
# is therefore DERIVED: floor created_at to the most recent grid mark. Honest
# limitation: a MANUAL dispatch off the grid also floors backwards, giving C3's
# staleness bound up to ~30 min of slack for that run — accepted, because
# manual dispatches are human-attended acceptance tests, and the grid events
# (native cron and the waker) land on the marks. Fallback to now is the
# CONSERVATIVE direction (it can only make staleness stricter), and it is
# recorded rather than hidden. The FUTURE bound of C3 deliberately does NOT use
# this slot — see check_c3_freshness.
EVENT_NAME="${GH_EVENT_NAME:-unknown}"
NOW_EPOCH=$(date -u +%s)
REF_EPOCH=$NOW_EPOCH; REF_SOURCE="now-fallback"; QUEUE_DELAY_S=""
if [ -n "${GH_RUN_CREATED_AT:-}" ]; then
  QUEUED_EPOCH=$(date -d "$GH_RUN_CREATED_AT" +%s 2>/dev/null) || QUEUED_EPOCH=""
  case "$QUEUED_EPOCH" in
    ''|*[!0-9]*) : ;;  # unparseable -> keep the recorded fallback
    *)
      MIN_PAST_HOUR=$(( (QUEUED_EPOCH / 60) % 60 ))
      if   [ "$MIN_PAST_HOUR" -ge 50 ]; then OFFSET_MIN=$(( MIN_PAST_HOUR - 50 ))
      elif [ "$MIN_PAST_HOUR" -ge 20 ]; then OFFSET_MIN=$(( MIN_PAST_HOUR - 20 ))
      else                                   OFFSET_MIN=$(( MIN_PAST_HOUR + 10 ))  # previous hour's :50
      fi
      REF_EPOCH=$(( QUEUED_EPOCH - OFFSET_MIN * 60 - QUEUED_EPOCH % 60 ))
      REF_SOURCE="grid-slot"
      QUEUE_DELAY_S=$(( QUEUED_EPOCH - REF_EPOCH ))
      ;;
  esac
fi
note "reference time: $REF_SOURCE ($(date -u -d "@$REF_EPOCH" +%Y-%m-%dT%H:%M:%SZ)) event=$EVENT_NAME${QUEUE_DELAY_S:+ queue_delay=${QUEUE_DELAY_S}s}"

# --- atomic fetch -------------------------------------------------------------
# One request per resource; headers and body from the same response. Three
# attempts with backoff absorb network hiccups, and needing them is RECORDED so
# C7 can see sustained degradation instead of it hiding behind the retry.
fetch() { # $1=url $2=body-out $3=headers-out -> echoes status
  local url="$1" body="$2" hdr="$3" i status
  for i in 1 2 3; do
    if curl -sS -D "$hdr" -o "$body" --max-time 30 "$url" 2>/dev/null; then
      status=$(head -1 "$hdr" | awk '{print $2}')
      [ -n "$status" ] && { echo "$status"; return 0; }
    fi
    [ $i -lt 3 ] && { RETRIED=true; sleep $((i * 10)); }
  done
  RETRIED=true; echo "000"; return 0
}

capture() {
  fetch "$TENANT_URL"        "$WORK/page.html"   "$WORK/page.hdr"   > "$WORK/page.status"
  fetch "$ANCHOR_URL"        "$WORK/chain.json"  "$WORK/chain.hdr"  > /dev/null
  fetch "$LEGACY_ANCHOR_URL?cb=$(date +%s)" "$WORK/legacy.json" "$WORK/legacy.hdr" > "$WORK/legacy.status"
  fetch "$LANDING_URL"       "$WORK/landing.html" "$WORK/landing.hdr" > "$WORK/landing.status"
  fetch "$BUNDLE_URL"        "$WORK/bundle.json" "$WORK/bundle.hdr" > /dev/null
}

capture
# If a publish landed mid-window, the page and the anchor legitimately disagree.
# Re-capture once and only alert if it persists  — otherwise C5c would
# go red with a perfectly healthy system every time a run met a publish.
FIRST_SUM=$(sha256sum "$WORK/chain.json" 2>/dev/null | cut -d' ' -f1)
capture
SECOND_SUM=$(sha256sum "$WORK/chain.json" 2>/dev/null | cut -d' ' -f1)
[ "$FIRST_SUM" != "$SECOND_SUM" ] && note "anchor changed mid-window; re-captured (publish in flight)"

# --- checks -------------------------------------------------------------------
run check_c1_http_200 "$WORK/page.hdr"

LANDING_STATUS=$(cat "$WORK/landing.status")
if [ "$LANDING_STATUS" != "200" ]; then
  note "C1b FAIL: landing HTTP $LANDING_STATUS (the commercial face is down)"
  RC=1
else
  # The landing is a single-page app: the Trust Center link is built by the
  # JS bundle and is NOT in the served HTML. Grepping the HTML would have been a
  # guaranteed false positive — found on the first real run. Follow the bundle
  # the HTML references, which is also what actually breaks if a future deploy
  # drops the link.
  BUNDLE=$(grep -oE 'src="/assets/[^"]+\.js"' "$WORK/landing.html" | head -1 | sed 's/src="//;s/"//')
  if [ -z "$BUNDLE" ]; then
    note "C1b FAIL: landing served no JS bundle reference (structure changed)"
    RC=1
  else
    curl -sS --max-time 30 -o "$WORK/bundle.js" "${LANDING_URL%/}$BUNDLE" 2>/dev/null
    if grep -qF "trust.seetrex.com" "$WORK/bundle.js"; then
      note "C1b ok: landing 200 and Trust Center link present in bundle"
    else
      note "C1b FAIL: Trust Center link absent from the landing bundle (dead end for prospects)"
      RC=1
    fi
  fi
fi

run check_c2_headers  "$WORK/page.hdr" "$ROOT/config/expected_headers.txt"
run check_c3_freshness "$WORK/page.html" "$REF_EPOCH" "$MAX_STALENESS_MIN" "$MIN_STALENESS_MIN" "$NOW_EPOCH"
run check_c4_identity "$WORK/page.html" "$WORK/chain.json" "$TENANT_SLUG" "$SCHEMA_VERSION"

"$VERIFIER_BIN" verify-chain "$WORK/chain.json" > "$WORK/vout.txt" 2>&1 || true
run check_c5a_verify_chain "$WORK/chain.json" "$VERIFIER_BIN"
run check_c5c_page_matches_anchor "$WORK/page.html" "$WORK/vout.txt"

WAS_DIVERGENT=0
[ -s "$DISPUTED" ] && grep -q '"c6_divergent":true' "$DISPUTED" 2>/dev/null && WAS_DIVERGENT=1
run check_c6_legacy_anchor "$WORK/chain.json" "$WORK/legacy.json" "$(cat "$WORK/legacy.status")" "$WAS_DIVERGENT"

run check_c7_flapping "$HISTORY" "$FLAP_WINDOW" "$FLAP_THRESHOLD"
run check_c8_evidence_age "$WORK/chain.json" "$REF_EPOCH" "$EVIDENCE_MAX_DAYS"
run check_c10_witness_bundle "$WORK/bundle.hdr" "$WORK/bundle.json" "$BUNDLE_VERSION" "$REF_EPOCH" "$MAX_BUNDLE_AGE_MIN" "$BUNDLE_BASELINE" "$MIN_BUNDLE_AGE_MIN" "$NOW_EPOCH"
run check_c11_enrolled_slugs "$WORK/bundle.json" "$ROOT/config/expected_slugs.txt"

CERT_LEFT=$(echo | openssl s_client -connect "$(echo "$TENANT_URL" | awk -F/ '{print $3}'):443" \
  -servername "$(echo "$TENANT_URL" | awk -F/ '{print $3}')" 2>/dev/null \
  | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
if [ -n "$CERT_LEFT" ]; then
  run check_c9_cert_expiry "$(( $(date -d "$CERT_LEFT" +%s) - $(date -u +%s) ))" "$CERT_MIN_DAYS"
else
  note "C9 FAIL: could not read certificate expiry"; RC=1
fi

# --- append-only witness ------------------------------------------------------
C5B_OUT=$(check_c5b_append_only "$WORK/chain.json" "$BASELINE" 2>&1); C5B_RC=$?
note "$C5B_OUT"; [ $C5B_RC -ne 0 ] && RC=1

# --- state --------------------------------------------------------------------
TIP=$(python3 -c "
import json,sys
c=json.load(open(sys.argv[1]))['chain']
t=max(c,key=lambda e:e['ordinal'])
print(t['ordinal'], t['chain_hash'], len(c))" "$WORK/chain.json" 2>/dev/null)
read -r TIP_ORD TIP_HASH TIP_COUNT <<< "${TIP:-0 none 0}"

# Missed grid windows since the previous observation's slot (grid = 1800 s).
# This is the honest record of the platform's real cadence (G46-8 input): a
# skipped window leaves no run and no red — only this counter sees it. `null`
# when either endpoint lacks a derived slot; never silently 0.
SLOT_EPOCH_JSON="null"; MISSED="null"
if [ "$REF_SOURCE" = "grid-slot" ]; then
  SLOT_EPOCH_JSON="$REF_EPOCH"
  # `[0-9]*` (zero-or-more) is DELIBERATE: a previous observation recorded with
  # "slot_epoch":null must still match here (empty numeric part -> cut yields
  # '' -> MISSED stays null). "Hardening" it to `[0-9]\+` would silently skip
  # null observations and compute missed_windows over a span the spec defines
  # as unknowable.
  PREV_SLOT_EPOCH=$(grep -o '"slot_epoch":[0-9]*' "$HISTORY" 2>/dev/null | tail -1 | cut -d: -f2)
  case "${PREV_SLOT_EPOCH:-}" in
    ''|*[!0-9]*) : ;;
    *)
      SLOT_DELTA=$(( REF_EPOCH - PREV_SLOT_EPOCH ))
      if [ "$SLOT_DELTA" -gt 0 ]; then
        MISSED=$(( SLOT_DELTA / 1800 - 1 ))
        [ "$MISSED" -lt 0 ] && MISSED=0
      elif [ "$SLOT_DELTA" -eq 0 ]; then
        MISSED=0   # same slot twice (overlap/rerun): both endpoints known, nothing skipped
      else
        MISSED="null"   # slot went BACKWARDS (time anomaly): unknowable, never a silent 0
      fi
      ;;
  esac
fi

printf '{"observed_at":"%s","ref_source":"%s","slot_epoch":%s,"event":"%s","queue_delay_s":%s,"missed_windows":%s,"ordinal":%s,"chain_hash":"%s","verdict_count":%s,"retried":%s,"verdict":"%s"}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REF_SOURCE" "$SLOT_EPOCH_JSON" "$EVENT_NAME" "${QUEUE_DELAY_S:-null}" "$MISSED" \
  "${TIP_ORD:-0}" "${TIP_HASH:-none}" \
  "${TIP_COUNT:-0}" "$RETRIED" "$([ $RC -eq 0 ] && echo pass || echo fail)" >> "$HISTORY"

if [ $RC -eq 0 ]; then
  # Baseline ADVANCES on green : pinned to a fixed past point, the
  # witness would never see a rewrite of anything after it.
  printf '{"ordinal":%s,"chain_hash":"%s","verdict_count":%s,"advanced_at":"%s"}\n' \
    "$TIP_ORD" "$TIP_HASH" "$TIP_COUNT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$BASELINE"
  # Same advance-on-green-only rule for the bundle size: a red run must never
  # re-baseline, or the rollback witness certifies the rollback. Written only
  # when the size parsed as a number — never junk into the witness state.
  BUNDLE_SIZE=$("$PY" -c "import json,sys;s=json.load(open(sys.argv[1])).get('c_audit',{}).get('size');print(s if isinstance(s,int) else '')" "$WORK/bundle.json" 2>/dev/null)
  case "${BUNDLE_SIZE:-}" in
    ''|*[!0-9]*) note "bundle baseline NOT advanced (size unparseable on a green run — should be unreachable, C10 gates it)" ;;
    *) printf '{"c_audit_size":%s,"advanced_at":"%s"}\n' "$BUNDLE_SIZE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$BUNDLE_BASELINE" ;;
  esac
  rm -f "$DISPUTED"
else
  # NEVER re-baseline on failure. A rewrite changes the state, so "write what we
  # saw" would let the witness certify the rewrite and forget it happened — the
  # alarm would be one-shot.
  printf '{"disputed_at":"%s","observed_ordinal":%s,"observed_hash":"%s","c6_divergent":%s,"reasons":%s}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${TIP_ORD:-0}" "${TIP_HASH:-none}" \
    "$(printf '%s' "$RESULTS" | grep -q 'C6 FAIL\|C6 ok(tolerated)' && echo true || echo false)" \
    "$(printf '%s' "$RESULTS" | grep 'FAIL' | python3 -c 'import json,sys;print(json.dumps([l.strip() for l in sys.stdin]))')" \
    > "$DISPUTED"
  echo "--- DISPUTED: staying red every run until a human acknowledges by commit ---"
fi

exit $RC
