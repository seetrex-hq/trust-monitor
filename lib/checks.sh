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
    # Skip blanks AND comments. Without the comment guard the whole header of
    # the config file was parsed as header names, so C2 reported a wall of
    # nonsense as "missing headers" on the very first real run.
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
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
# STALENESS is measured against the SCHEDULED slot, not execution time, so
# platform delay does not contaminate the measurement. The FUTURE bound is
# measured against the WALL CLOCK instead: a page generated after the slot is
# a normal publish landing mid-window on a delayed run; only a timestamp ahead
# of NOW indicates a compromised or skewed publisher clock. Coupling both
# bounds to the slot produced false "clock compromised" reds (2026-07-26
# review) — false positives are what kill monitoring.
# $1 = page file, $2 = reference epoch (slot), $3 = max minutes,
# $4 = min minutes (negative), $5 = wall-clock epoch (defaults to $2)
check_c3_freshness() {
  local page="$1" ref_epoch="$2" max_min="$3" min_min="$4" now_epoch="${5:-$2}" iso page_epoch delta future_delta
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
  future_delta=$(( (now_epoch - page_epoch) / 60 ))
  if [ "$future_delta" -lt "$min_min" ]; then
    echo "C3 FAIL: generated_at is ${future_delta}min in the FUTURE of the wall clock (host clock compromised; a published timestamp can never be ahead)"
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

# --- C10: the public witness bundle --------------------------------------------
# The bundle is the only post-gamma surface without an external witness: the
# internal heartbeat shares fate with the host it watches. Structural +
# anti-rollback only (founder decision 2026-07-26): no crypto re-verification
# here — that would duplicate the on-host witness; what an EXTERNAL monitor can
# honestly attest is that the bundle is served, is the expected document, keeps
# being republished, and never rolls back.
# Freshness uses Last-Modified against the SCHEDULED slot (same reasoning as
# C3's upper bound): the pipeline re-copies the bundle hourly at :05, so a
# fresh mtime proves "the publisher is alive", while the CONTENT advances on
# the witness's own daily cadence — which is exactly what the size baseline
# watches instead.
# $1 = headers file, $2 = body file, $3 = expected version, $4 = reference
# epoch (slot), $5 = max age minutes, $6 = baseline file ("" if bootstrapping)
check_c10_witness_bundle() {
  local headers="$1" body="$2" want_version="$3" ref_epoch="$4" max_min="$5" baseline="$6"
  local status lastmod lm_epoch age_min

  status=$(head -1 "$headers" | awk '{print $2}')
  if [ "$status" != "200" ]; then
    echo "C10 FAIL: bundle HTTP $status (published contract: witness-bundle.json stays 200)"
    return 1
  fi

  lastmod=$(grep -i '^last-modified:' "$headers" | head -1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r')
  if [ -z "$lastmod" ]; then
    echo "C10 FAIL: Last-Modified header absent — freshness unmeasurable, and unmeasurable must be loud"
    return 1
  fi
  if ! lm_epoch=$(date -d "$lastmod" +%s 2>/dev/null); then
    echo "C10 FAIL: Last-Modified unparseable: $lastmod"
    return 1
  fi
  age_min=$(( (ref_epoch - lm_epoch) / 60 ))
  if [ "$age_min" -gt "$max_min" ]; then
    echo "C10 FAIL: bundle is ${age_min}min stale (budget ${max_min}min vs the hourly republish — publisher likely dead)"
    return 1
  fi

  "$PY" - "$body" "$want_version" "$baseline" "$age_min" <<'PYEOF'
import json, sys
try:
    bundle = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"C10 FAIL: bundle unparseable as JSON: {e}"); sys.exit(1)
got = bundle.get("version", "")
if got != sys.argv[2]:
    print(f"C10 FAIL: version '{got}' != expected '{sys.argv[2]}' (COUPLING: see README)"); sys.exit(1)
size = bundle.get("c_audit", {}).get("size")
if not isinstance(size, int) or isinstance(size, bool):
    print("C10 FAIL: c_audit.size absent or non-numeric"); sys.exit(1)
if not bundle.get("leaves"):
    print("C10 FAIL: no leaves — a bundle that explains none of our facts witnesses nothing"); sys.exit(1)
base_path = sys.argv[3]
try:
    f = open(base_path)
except FileNotFoundError:
    # ONLY a missing file is bootstrap. A baseline that exists but cannot be
    # read or parsed is C5b's rule: loud red, never silent re-adoption — a
    # rollback landing in the same window as a corruption/permission break
    # would otherwise be certified, and a green run would then REWRITE the
    # baseline over whatever the witness had pinned.
    print(f"C10 BOOTSTRAP: no bundle baseline; adopting c_audit.size {size} AND SAYING SO (never silently)")
    sys.exit(0)
except OSError as e:
    print(f"C10 FAIL: bundle baseline unreadable ({type(e).__name__}) — refusing to re-adopt over a corrupt witness"); sys.exit(1)
try:
    base_size = json.load(f)["c_audit_size"]
except Exception as e:
    print(f"C10 FAIL: bundle baseline unreadable ({type(e).__name__}) — refusing to re-adopt over a corrupt witness"); sys.exit(1)
if size < base_size:
    print(f"C10 FAIL: c_audit.size SHRANK {base_size} -> {size} — the audited log can only grow"); sys.exit(1)
print(f"C10 ok: bundle {sys.argv[4]}min old, version pinned, c_audit.size {base_size} -> {size}")
PYEOF
}

# --- C11: per-slug enrollment floor (F-B.2-c E2-6, 2026-07-26) -----------------
# Since witness 0.2.0 the bundle explains N tenants, and a SCALAR minimum
# ("some leaves exist") stops discriminating: a bundle green on dogfood alone
# looks identical to one green on every onboarded tenant (#84 reviews A-1/B-3).
# The floor an EXTERNAL monitor can honestly hold: every slug pinned here has
# its ENROLL lane explained in the bundle. ENROLL only — heads accrue on the
# tenants' own publishing cadence and a freshly-enrolled tenant with no head
# yet is healthy, not red (false positives kill monitoring).
# The pinned list is deliberate operator config, exactly like the version pin:
# onboarding a tenant ends by ADDING its slug here (COUPLING). An ENROLL in the
# bundle for a slug NOT pinned is loud too — under OUR submit key it is either
# config lag after an onboarding or an identity nobody authorized; both must
# alarm, never blend into green.
# $1 = bundle body file, $2 = expected-slugs file (one slug per line, # comments)
check_c11_enrolled_slugs() {
  local body="$1" expected_file="$2"
  if [ ! -s "$expected_file" ]; then
    echo "C11 FAIL: expected-slugs config missing or empty — an empty floor checks nothing, and unmeasurable must be loud"
    return 1
  fi
  "$PY" - "$body" "$expected_file" <<'PYEOF'
import json, sys
try:
    bundle = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"C11 FAIL: bundle unparseable as JSON: {e}"); sys.exit(1)
if not isinstance(bundle, dict):
    print("C11 FAIL: bundle is valid JSON but not an object — wrong document"); sys.exit(1)
try:
    config_lines = open(sys.argv[2]).read().splitlines()
except OSError as e:
    # The shell guard catches absent/empty; this catches the existing-but-
    # unreadable file (permissions, a directory passing -s). Same doctrine:
    # an unreadable floor checks nothing, and unmeasurable must be loud —
    # and as a one-line reason, never a traceback (2026-07-26 review).
    print(f"C11 FAIL: expected-slugs config unreadable ({type(e).__name__}) — an unreadable floor checks nothing, and unmeasurable must be loud"); sys.exit(1)
expected = []
for line in config_lines:
    line = line.strip()
    if line and not line.startswith("#"):
        if line in expected:
            print(f"C11 FAIL: duplicate slug '{line}' in expected_slugs.txt — a fat-fingered pin gets fixed, never counted twice"); sys.exit(1)
        expected.append(line)
if not expected:
    print("C11 FAIL: expected-slugs config missing or empty — an empty floor checks nothing, and unmeasurable must be loud")
    sys.exit(1)
leaves = bundle.get("leaves", [])
if not isinstance(leaves, list):
    print("C11 FAIL: leaves is not a list — wrong or degenerate bundle shape"); sys.exit(1)
enrolled = set()
for leaf in leaves:
    lane = (leaf.get("lane") if isinstance(leaf, dict) else None) or {}
    if isinstance(lane, dict) and lane.get("kind") == "enroll":
        slug = lane.get("slug")
        if not (isinstance(slug, str) and slug):
            # A degenerate enroll under OUR submit key is an identity claim
            # with no name: skipping it silently would certify it as part of
            # a green bundle (2026-07-26 review, sev 45).
            print("C11 FAIL: enroll lane with missing/empty slug — a degenerate identity under our submit key must never blend into green"); sys.exit(1)
        enrolled.add(slug)
missing = [s for s in expected if s not in enrolled]
extra = sorted(enrolled - set(expected))
if missing:
    print(f"C11 FAIL: enrollment floor broken — pinned slug(s) with NO enroll lane in the bundle: {', '.join(missing)}")
    sys.exit(1)
if extra:
    print(f"C11 FAIL: enroll lane(s) for slug(s) not pinned in expected_slugs.txt: {', '.join(extra)} (COUPLING: onboarding ends by updating the pin; an unauthorized identity under our key must never blend into green)")
    sys.exit(1)
print(f"C11 ok: enrollment floor met for {len(expected)} slug(s): {', '.join(expected)}")
PYEOF
}
