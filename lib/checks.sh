#!/usr/bin/env bash
# Trust Center external monitor — check library.
#
# Every check is a pure function over ALREADY-FETCHED local files. That is what
# makes the canary possible : the canary feeds these same functions
# known-bad fixtures and demands that each one fails. If the checks only existed
# inline in the workflow, a check that silently stopped checking would be
# undetectable — the very failure class this monitor exists to prevent,
# reproduced inside the monitor itself.
#
# Contract: every check_* returns 0 (pass) or 1 (fail) and writes a one-line
# human reason to stdout. No check reads the network. No check exits the shell.
#
# NEVER add `set -x` or `curl -v` anywhere in this repository: the run logs are
# public and DEADMAN_PING_URL is a capability to silence the alarm.

set -uo pipefail

# --- interpreter preflight ----------------------------------------------------
# Caught while testing the canary: on a box without `python3`
# the checks that use it died with exit 127, and the canary — which only asked
# "did it fail?" — reported them as healthy. A check that cannot even run must
# be LOUD, never silently indistinguishable from a check that works.
PY="${PY:-}"
if [ -z "$PY" ]; then
  if command -v python3 >/dev/null 2>&1; then PY=python3
  elif command -v python >/dev/null 2>&1; then PY=python
  else
    echo "FATAL: no python interpreter (python3/python) — the checks that parse the chain cannot run"
    exit 78
  fi
fi

# --- C1: the tenant page answered 200 -----------------------------------------
# $1 = headers file
check_c1_http_200() {
  local headers="$1" status
  status=$(head -1 "$headers" | awk '{print $2}')
  if [ "$status" != "200" ]; then
    echo "C1 FAIL: HTTP $status (no -L on purpose: an unexpected 301 must alarm, not self-heal)"
    return 1
  fi
  echo "C1 ok: HTTP 200"
}

# --- C2: the five E.6 security headers, present AND with the expected value ---
# Presence alone is not enough: a a server-side config repair that rewrites values rather
# than deleting keys would be invisible.
# $1 = headers file, $2 = expected-values file (`header: substring` per line)
check_c2_headers() {
  local headers="$1" expected="$2" missing="" wrong="" name want got
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    name=$(printf '%s' "$line" | cut -d: -f1 | tr '[:upper:]' '[:lower:]')
    want=$(printf '%s' "$line" | cut -d: -f2- | sed 's/^ *//')
    got=$(grep -i "^$name:" "$headers" | head -1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r')
    if [ -z "$got" ]; then
      missing="$missing $name"
    elif ! printf '%s' "$got" | grep -qF "$want"; then
      wrong="$wrong $name"
    fi
  done < "$expected"
  if [ -n "$missing" ] || [ -n "$wrong" ]; then
    echo "C2 FAIL: missing:${missing:- none} degraded-value:${wrong:- none}"
    return 1
  fi
  echo "C2 ok: 5 headers present with expected values"
}

# --- C3: freshness, with BOTH bounds ------------------------------------------
# Upper bound catches a dead publisher. The LOWER bound catches the eternal
# false negative : NTP breaks, the host clock jumps forward, the last
# publish is stamped in the future, the cron dies, and the delta stays negative
# FOREVER while every indicator is green.
#
# Reference time is the SCHEDULED time, not execution time, so platform delay
# does not contaminate the measurement.
# $1 = page file, $2 = reference epoch, $3 = max minutes, $4 = min minutes (negative)
check_c3_freshness() {
  local page="$1" ref_epoch="$2" max_min="$3" min_min="$4" iso page_epoch delta
  iso=$(grep -oE 'generated at <code>[^<]+' "$page" | sed 's/.*<code>//' | head -1)
  if [ -z "$iso" ]; then
    echo "C3 FAIL: generated_at badge not found in page"
    return 1
  fi
  if ! page_epoch=$(date -d "$iso" +%s 2>/dev/null); then
    echo "C3 FAIL: generated_at unparseable: $iso"
    return 1
  fi
  delta=$(( (ref_epoch - page_epoch) / 60 ))
  if [ "$delta" -gt "$max_min" ]; then
    echo "C3 FAIL: page is ${delta}min stale (budget ${max_min}min, measured against scheduled time)"
    return 1
  fi
  if [ "$delta" -lt "$min_min" ]; then
    echo "C3 FAIL: generated_at is ${delta}min in the FUTURE (host clock compromised; a published timestamp can never be ahead)"
    return 1
  fi
  echo "C3 ok: generated_at ${iso} delta=${delta}min"
}

# --- C4: identity of what we are looking at -----------------------------------
# A 200 with headers and some timestamp is not proof we are looking at the right
# document . Pins the tenant slug and the anchor schema version.
# $1 = page file, $2 = chain json, $3 = expected slug, $4 = expected schema_version
check_c4_identity() {
  local page="$1" chain="$2" slug="$3" schema="$4" got_schema
  if ! grep -qF "$slug" "$page"; then
    echo "C4 FAIL: tenant slug '$slug' not present in served page"
    return 1
  fi
  got_schema=$("$PY" -c "import json,sys;print(json.load(open(sys.argv[1])).get('schema_version',''))" "$chain" 2>/dev/null)
  if [ "$got_schema" != "$schema" ]; then
    echo "C4 FAIL: anchor schema_version '$got_schema' != expected '$schema' (COUPLING: see README)"
    return 1
  fi
  echo "C4 ok: slug and schema_version match"
}

# --- C5a: OUR OWN published verifier ------------------------------------------
# The whole point : without this the monitor only compares the chain
# against its own memory, so a chain with severed links keeps every check green
# while an auditor following the page gets CHAIN BROKEN.
# $1 = chain json, $2 = verifier binary
check_c5a_verify_chain() {
  local chain="$1" bin="$2" out rc
  out=$("$bin" verify-chain "$chain" 2>&1); rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "C5a FAIL: verify-chain exit $rc: $(printf '%s' "$out" | head -2 | tr '\n' ' ')"
    return 1
  fi
  echo "C5a ok: $(printf '%s' "$out" | head -1)"
}

# --- C5b: append-only witness -------------------------------------------------
# Exercises continuously what verify.html tells the auditor to do: keep your
# copy, every future export must EXTEND, never REWRITE, the prefix you verified.
# Deliberately does NOT alert on a stalled count: the anti-inflation gate makes a
# flat verdict_count legitimate for days, and false positives are what kill
# monitoring systems. Liveness is C3's job.
# $1 = chain json, $2 = baseline json ("" if bootstrapping)
check_c5b_append_only() {
  local chain="$1" baseline="$2"
  if [ ! -s "$baseline" ]; then
    echo "C5b BOOTSTRAP: no baseline; adopting current tip AND SAYING SO (never silently)"
    return 0
  fi
  "$PY" - "$chain" "$baseline" <<'PYEOF'
import json, sys
chain = json.load(open(sys.argv[1]))["chain"]
base = json.load(open(sys.argv[2]))
count = len(chain)
if count < base["verdict_count"]:
    print(f"C5b FAIL: chain SHRANK {base['verdict_count']} -> {count}")
    sys.exit(1)
match = [e for e in chain if e["ordinal"] == base["ordinal"]]
if not match:
    print(f"C5b FAIL: pinned ordinal {base['ordinal']} ABSENT from the published chain")
    sys.exit(1)
if match[0]["chain_hash"] != base["chain_hash"]:
    print(f"C5b FAIL: prefix REWRITTEN at ordinal {base['ordinal']}: "
          f"{base['chain_hash'][:16]}... -> {match[0]['chain_hash'][:16]}...")
    sys.exit(1)
print(f"C5b ok: prefix intact at ordinal {base['ordinal']}, count {base['verdict_count']} -> {count}")
PYEOF
}

# --- C5c: the page and the anchor agree ---------------------------------------
# Partial-publish divergence is the most likely failure and neither C5a nor C5b
# sees it: both only look at the JSON.
# $1 = page file, $2 = verifier output file
check_c5c_page_matches_anchor() {
  local page="$1" vout="$2" a_count a_hash p_count p_hash
  a_count=$(grep -oE 'verdict_count:[[:space:]]+[0-9]+' "$vout" | grep -oE '[0-9]+$')
  a_hash=$(grep -oE 'last_chain_hash:[[:space:]]+[0-9a-f]+' "$vout" | grep -oE '[0-9a-f]+$')
  p_count=$(grep -oE '<dd>[0-9]+</dd>' "$page" | grep -oE '[0-9]+' | head -1)
  p_hash=$(grep -oE '[0-9a-f]{64}' "$page" | head -1)
  if [ -z "$a_count" ] || [ -z "$a_hash" ]; then
    echo "C5c FAIL: could not parse verifier output (verifier contract changed?)"
    return 1
  fi
  if [ "$a_count" != "$p_count" ] || [ "$a_hash" != "$p_hash" ]; then
    echo "C5c FAIL: page/anchor divergence — page(count=$p_count hash=${p_hash:0:16}) anchor(count=$a_count hash=${a_hash:0:16})"
    return 1
  fi
  echo "C5c ok: page and anchor agree (count=$a_count)"
}

# --- C6: historic anchor, CONVERGENCE not instant equality --------------------
# The legacy anchor is served through Cloudflare and may come from edge cache
# while the new one already moved on. Demanding instant equality across two
# different paths would go red every time the chain grows.
# $1 = new anchor, $2 = legacy anchor, $3 = legacy http status, $4 = 1 if already divergent last run
check_c6_legacy_anchor() {
  local new="$1" legacy="$2" status="$3" was_divergent="$4" h_new h_legacy
  if [ "$status" != "200" ]; then
    echo "C6 FAIL: legacy anchor HTTP $status (published contract: this URL stays 200)"
    return 1
  fi
  h_new=$(sha256sum "$new" | cut -d' ' -f1)
  h_legacy=$(sha256sum "$legacy" | cut -d' ' -f1)
  if [ "$h_new" = "$h_legacy" ]; then
    echo "C6 ok: dual anchor byte-identical"
    return 0
  fi
  if [ "$was_divergent" = "1" ]; then
    echo "C6 FAIL: dual anchor divergence SUSTAINED across runs (not edge-cache propagation)"
    return 1
  fi
  echo "C6 ok(tolerated): anchors differ this run; convergence pending, will fail if sustained"
}

# --- C7: sustained degradation, by RATE not by consecutive runs ---------------
# "Two consecutive runs" sounds strict and is not: with nginx failing 20% of
# requests the expected time to two consecutive retry-runs is ~25h while one in
# five prospects sees an error.
# $1 = history file, $2 = window size, $3 = threshold
check_c7_flapping() {
  local history="$1" window="$2" threshold="$3" hits
  [ -s "$history" ] || { echo "C7 ok: no history yet"; return 0; }
  hits=$(tail -n "$window" "$history" | grep -c '"retried":true' || true)
  if [ "$hits" -ge "$threshold" ]; then
    echo "C7 FAIL: $hits of last $window observations needed retries — sustained degradation, not a network hiccup"
    return 1
  fi
  echo "C7 ok: $hits/$window observations retried"
}

# --- C8: evidence rot (PARTIAL coverage, by design) ---------------------------
# A dead pipeline republishing hourly has a fresh generated_at by construction
# (build time, not data time), so C3 cannot see it. Loose threshold only.
# $1 = chain json, $2 = reference epoch, $3 = max days
check_c8_evidence_age() {
  local chain="$1" ref="$2" max_days="$3"
  "$PY" - "$chain" "$ref" "$max_days" <<'PYEOF'
import json, sys, datetime
chain = json.load(open(sys.argv[1]))["chain"]
ref, max_days = int(sys.argv[2]), int(sys.argv[3])
if not chain:
    print("C8 FAIL: empty chain"); sys.exit(1)
newest = max(e["appended_at"] for e in chain)
ts = datetime.datetime.fromisoformat(newest.replace("Z", "+00:00")).timestamp()
age = (ref - ts) / 86400
if age > max_days:
    print(f"C8 FAIL: newest verdict is {age:.1f} days old (>{max_days}) — pipeline likely dead while the page stays fresh")
    sys.exit(1)
print(f"C8 ok: newest verdict {age:.1f} days old")
PYEOF
}

# --- C9: certificate expiry, BEFORE it becomes an outage ----------------------
# $1 = seconds remaining, $2 = minimum days
check_c9_cert_expiry() {
  # Split deliberately: bash expands every word of a `local` before assigning
  # any of them, so computing days in the same statement referenced `remaining`
  # before it existed. Caught by the canary — which is the point of the canary.
  local remaining="$1" min_days="$2"
  local days=$(( remaining / 86400 ))
  if [ "$days" -lt "$min_days" ]; then
    echo "C9 FAIL: TLS certificate expires in ${days}d (< ${min_days}d) — turns a 3h incident into planned maintenance"
    return 1
  fi
  echo "C9 ok: certificate valid for ${days}d"
}
