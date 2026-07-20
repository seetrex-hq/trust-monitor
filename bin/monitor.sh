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
: "${VERIFIER_BIN:?}"
MAX_STALENESS_MIN="${MAX_STALENESS_MIN:-90}"
MIN_STALENESS_MIN="${MIN_STALENESS_MIN:--5}"
EVIDENCE_MAX_DAYS="${EVIDENCE_MAX_DAYS:-30}"
CERT_MIN_DAYS="${CERT_MIN_DAYS:-14}"
FLAP_WINDOW="${FLAP_WINDOW:-6}"
FLAP_THRESHOLD="${FLAP_THRESHOLD:-2}"

STATE="$ROOT/state"; mkdir -p "$STATE"
HISTORY="$STATE/history.jsonl"; BASELINE="$STATE/baseline.json"
DISPUTED="$STATE/disputed.json"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
RETRIED=false; RESULTS=""; RC=0

note() { RESULTS="$RESULTS$1"$'\n'; echo "$1"; }
run()  { local out; out=$("$@" 2>&1); local rc=$?; note "$out"; [ $rc -ne 0 ] && RC=1; return 0; }

# --- reference time: the SCHEDULED slot, not now ------------------------------
# Platform delay must not contaminate staleness . GitHub's
# run `created_at` is when the run was queued, i.e. the scheduled moment.
# Fallback to now is the CONSERVATIVE direction (it can only make us stricter),
# and it is recorded rather than hidden.
REF_EPOCH=$(date -u +%s); REF_SOURCE="now-fallback"
if [ -n "${GH_RUN_CREATED_AT:-}" ]; then
  if REF_EPOCH=$(date -d "$GH_RUN_CREATED_AT" +%s 2>/dev/null); then
    REF_SOURCE="scheduled"
  else
    REF_EPOCH=$(date -u +%s)
  fi
fi
note "reference time: $REF_SOURCE ($(date -u -d "@$REF_EPOCH" +%Y-%m-%dT%H:%M:%SZ))"

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
if [ "$LANDING_STATUS" = "200" ] && grep -qF "trust.seetrex.com" "$WORK/landing.html"; then
  note "C1b ok: landing 200 and Trust Center link present"
else
  note "C1b FAIL: landing status $LANDING_STATUS or Trust Center link missing (the commercial face)"
  RC=1
fi

run check_c2_headers  "$WORK/page.hdr" "$ROOT/config/expected_headers.txt"
run check_c3_freshness "$WORK/page.html" "$REF_EPOCH" "$MAX_STALENESS_MIN" "$MIN_STALENESS_MIN"
run check_c4_identity "$WORK/page.html" "$WORK/chain.json" "$TENANT_SLUG" "$SCHEMA_VERSION"

"$VERIFIER_BIN" verify-chain "$WORK/chain.json" > "$WORK/vout.txt" 2>&1 || true
run check_c5a_verify_chain "$WORK/chain.json" "$VERIFIER_BIN"
run check_c5c_page_matches_anchor "$WORK/page.html" "$WORK/vout.txt"

WAS_DIVERGENT=0
[ -s "$DISPUTED" ] && grep -q '"c6_divergent":true' "$DISPUTED" 2>/dev/null && WAS_DIVERGENT=1
run check_c6_legacy_anchor "$WORK/chain.json" "$WORK/legacy.json" "$(cat "$WORK/legacy.status")" "$WAS_DIVERGENT"

run check_c7_flapping "$HISTORY" "$FLAP_WINDOW" "$FLAP_THRESHOLD"
run check_c8_evidence_age "$WORK/chain.json" "$REF_EPOCH" "$EVIDENCE_MAX_DAYS"

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

printf '{"observed_at":"%s","ref_source":"%s","ordinal":%s,"chain_hash":"%s","verdict_count":%s,"retried":%s,"verdict":"%s"}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REF_SOURCE" "${TIP_ORD:-0}" "${TIP_HASH:-none}" \
  "${TIP_COUNT:-0}" "$RETRIED" "$([ $RC -eq 0 ] && echo pass || echo fail)" >> "$HISTORY"

if [ $RC -eq 0 ]; then
  # Baseline ADVANCES on green : pinned to a fixed past point, the
  # witness would never see a rewrite of anything after it.
  printf '{"ordinal":%s,"chain_hash":"%s","verdict_count":%s,"advanced_at":"%s"}\n' \
    "$TIP_ORD" "$TIP_HASH" "$TIP_COUNT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$BASELINE"
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
