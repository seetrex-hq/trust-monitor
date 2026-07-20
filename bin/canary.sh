#!/usr/bin/env bash
# C0 — the canary.
#
# Feeds every check a known-bad fixture and demands that it FAILS. If any check
# has stopped checking — a stray `|| true`, a comparison that is always true
# after a refactor, a `continue-on-error` added to "reduce noise" — the job goes
# RED and DOES NOT PING, so the dead-man's switch fires too.
#
# Without this, a monitor that silently stopped monitoring would report green
# forever: that is exactly the class this monitor exists to prevent, reappearing inside the monitor.
#
# ONE FIXTURE PER CHECK, not a sample: v2 of the design had 4 fixtures for 10
# checks, so a refactor breaking C5c left the canary green and page/anchor
# divergence undetectable again.
#
# Fixtures are GENERATED here rather than committed, so relative timestamps
# cannot rot and the canary keeps meaning the same thing in a year.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/../lib/checks.sh"

FIX="$(mktemp -d)"; trap 'rm -rf "$FIX"' EXIT
NOW=$(date -u +%s)
FAILED=0

# expect_fail <label> <expected-marker> <command...>
#
# The check must fail AND say why, with the marker of the check that was
# supposed to catch it.
#
# Asking only "did it fail?" is not enough, and this is not theoretical: caught empirically on a box without `python3` the chain-parsing checks died
# with exit 127 (`command not found`) and this function reported all of them as
# healthy. A check that cannot even run looked exactly like a check in perfect
# shape — the silent-green class, inside the very thing built to prevent it.
expect_fail() {
  local label="$1" marker="$2"; shift 2
  local out; out=$("$@" 2>&1); local rc=$?
  if [ $rc -eq 0 ]; then
    echo "CANARY BROKEN: $label did NOT fail on its known-bad fixture — this check has stopped checking"
    FAILED=1
  elif ! printf '%s' "$out" | grep -qF "$marker"; then
    echo "CANARY BROKEN: $label failed for the WRONG REASON (expected '$marker'): $(printf '%s' "$out" | head -1)"
    FAILED=1
  else
    echo "canary ok: $label rejected its fixture, and for the right reason"
  fi
}

# ---- fixtures ---------------------------------------------------------------
printf 'HTTP/2 502 \ncontent-type: text/html\n'                 > "$FIX/headers_502.txt"
printf 'HTTP/2 200 \ncontent-security-policy: default-src *\n'  > "$FIX/headers_weak_csp.txt"
printf 'content-security-policy: default-src '\''self'\''\n'    > "$FIX/expected_headers.txt"

STALE=$(date -u -d "@$((NOW - 7200))" +%Y-%m-%dT%H:%M:%SZ)
FUTURE=$(date -u -d "@$((NOW + 7200))" +%Y-%m-%dT%H:%M:%SZ)
printf '<p>generated at <code>%s</code></p>\n' "$STALE"  > "$FIX/page_stale.html"
printf '<p>generated at <code>%s</code></p>\n' "$FUTURE" > "$FIX/page_future.html"
printf '<p>no badge here at all</p>\n'                   > "$FIX/page_nobadge.html"
printf '<html>wrong-tenant</html>\n'                     > "$FIX/page_wrongslug.html"

OLD=$(date -u -d "@$((NOW - 86400*90))" +%Y-%m-%dT%H:%M:%SZ)
FRESH=$(date -u -d "@$NOW" +%Y-%m-%dT%H:%M:%SZ)

cat > "$FIX/chain_ok.json" <<EOF
{"schema_version":"1.0","chain":[
 {"ordinal":1,"chain_prev_hash":null,"chain_hash":"aaa","appended_at":"$FRESH"},
 {"ordinal":2,"chain_prev_hash":"aaa","chain_hash":"bbb","appended_at":"$FRESH"}]}
EOF
cat > "$FIX/chain_rewritten.json" <<EOF
{"schema_version":"1.0","chain":[
 {"ordinal":1,"chain_prev_hash":null,"chain_hash":"aaa","appended_at":"$FRESH"},
 {"ordinal":2,"chain_prev_hash":"aaa","chain_hash":"ZZZ-REWRITTEN","appended_at":"$FRESH"}]}
EOF
cat > "$FIX/chain_shrunk.json" <<EOF
{"schema_version":"1.0","chain":[
 {"ordinal":1,"chain_prev_hash":null,"chain_hash":"aaa","appended_at":"$FRESH"}]}
EOF
cat > "$FIX/chain_rancid.json" <<EOF
{"schema_version":"1.0","chain":[
 {"ordinal":1,"chain_prev_hash":null,"chain_hash":"aaa","appended_at":"$OLD"}]}
EOF
cat > "$FIX/chain_badschema.json" <<EOF
{"schema_version":"99.0","chain":[
 {"ordinal":1,"chain_prev_hash":null,"chain_hash":"aaa","appended_at":"$FRESH"}]}
EOF
printf '{"ordinal":2,"chain_hash":"bbb","verdict_count":2}\n' > "$FIX/baseline.json"

printf 'Public chain package VERIFIED OFFLINE\n  verdict_count:   2\n  last_chain_hash: %s\n' \
  "$(printf 'b%.0s' {1..64})" > "$FIX/vout.txt"
printf '<dd>999</dd><span>%s</span>\n' "$(printf 'c%.0s' {1..64})" > "$FIX/page_divergent.html"

printf '{"retried":true}\n%.0s' {1..6} > "$FIX/history_flapping.jsonl"

# ---- one expectation per check ----------------------------------------------
expect_fail "C1 (http 200)"          "C1 FAIL" check_c1_http_200      "$FIX/headers_502.txt"
expect_fail "C2 (header VALUES)"     "C2 FAIL" check_c2_headers       "$FIX/headers_weak_csp.txt" "$FIX/expected_headers.txt"
expect_fail "C3 upper (stale)"       "C3 FAIL" check_c3_freshness     "$FIX/page_stale.html"   "$NOW" 90 -5
expect_fail "C3 LOWER (future)"      "FUTURE"  check_c3_freshness     "$FIX/page_future.html"  "$NOW" 90 -5
expect_fail "C3 (badge absent)"      "C3 FAIL" check_c3_freshness     "$FIX/page_nobadge.html" "$NOW" 90 -5
expect_fail "C4 (wrong slug)"        "C4 FAIL" check_c4_identity      "$FIX/page_wrongslug.html" "$FIX/chain_ok.json" "seetrex-compliance" "1.0"
expect_fail "C4 (schema bump)"       "C4 FAIL" check_c4_identity      "$FIX/page_stale.html" "$FIX/chain_badschema.json" "generated" "1.0"
expect_fail "C5b (rewritten prefix)" "REWRITTEN" check_c5b_append_only "$FIX/chain_rewritten.json" "$FIX/baseline.json"
expect_fail "C5b (chain shrank)"     "SHRANK"  check_c5b_append_only  "$FIX/chain_shrunk.json"    "$FIX/baseline.json"
expect_fail "C5c (page/anchor)"      "C5c FAIL" check_c5c_page_matches_anchor "$FIX/page_divergent.html" "$FIX/vout.txt"
expect_fail "C6 (legacy 404)"        "C6 FAIL" check_c6_legacy_anchor "$FIX/chain_ok.json" "$FIX/chain_ok.json" "404" "0"
expect_fail "C6 (sustained diff)"    "SUSTAINED" check_c6_legacy_anchor "$FIX/chain_ok.json" "$FIX/chain_shrunk.json" "200" "1"
expect_fail "C7 (flapping)"          "C7 FAIL" check_c7_flapping      "$FIX/history_flapping.jsonl" 6 2
expect_fail "C8 (evidence rot)"      "C8 FAIL" check_c8_evidence_age  "$FIX/chain_rancid.json" "$NOW" 30
expect_fail "C9 (cert expiry)"       "C9 FAIL" check_c9_cert_expiry   "$((86400 * 3))" 14

# C5a is exercised against a real broken chain only when the verifier binary is
# present; the workflow passes it. Skipped locally rather than faked, because a
# fake would defeat the purpose of the canary.
if [ -n "${VERIFIER_BIN:-}" ] && [ -x "${VERIFIER_BIN:-}" ]; then
  cat > "$FIX/chain_severed.json" <<EOF
{"schema_version":"1.0","chain":[
 {"ordinal":1,"verdict_id":"a","verdict_hash":"11","chain_prev_hash":null,"chain_hash":"aa","appended_at":"$FRESH","ruleset_id":"r","verdict_outcome":"SATISFIED"},
 {"ordinal":2,"verdict_id":"b","verdict_hash":"22","chain_prev_hash":"DESYNCED","chain_hash":"bb","appended_at":"$FRESH","ruleset_id":"r","verdict_outcome":"SATISFIED"}]}
EOF
  expect_fail "C5a (severed links)" "C5a FAIL" check_c5a_verify_chain "$FIX/chain_severed.json" "$VERIFIER_BIN"
else
  echo "CANARY BROKEN: VERIFIER_BIN not provided — C5a, the check that verifies the actual chain, would go unexercised"
  FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
  echo "CANARY FAILED — the monitor is not trustworthy this run; going red WITHOUT pinging."
  exit 1
fi
echo "canary: all checks proved they still detect their failure mode"
