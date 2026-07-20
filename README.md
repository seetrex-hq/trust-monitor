# trust-monitor

Independent, external monitoring of the **Seetrex Compliance Trust Center**
([trust.seetrex.com](https://trust.seetrex.com)).

Seetrex publishes an append-only chain of verdict hashes and invites anyone to
verify it offline with the open-source
[`seetrex-verifier`](https://github.com/seetrex-hq/seetrex-verifier). This
repository is the other half of that claim: a watchdog that checks, every 30
minutes and **from outside Seetrex's infrastructure**, that the published record
is actually reachable, fresh, internally consistent, and — most importantly —
that its history is never rewritten.

## Why an external repository

A monitor that runs beside the service it watches shares its fate. Whatever
takes the service down can take the watchdog and its alert channel with it, and
the resulting silence is indistinguishable from health. This job runs on
someone else's computer, on someone else's clock, and alerts through someone
else's network.

There is a second layer for the same reason: **a scheduler-based monitor cannot
detect its own silence**. If a scheduled run is skipped there is no failed run —
there is no run at all, and nobody is notified. A third-party dead-man's switch
therefore watches this job: if it stops reporting, the switch raises the alarm.
That is where the "who watches the watcher" recursion is cut, at a party whose
failure is independent of both Seetrex and this repository.

## What it checks

| Check | What it proves |
|---|---|
| C0 | **The canary** — every check below is fed a known-bad fixture and must reject it, *for the right reason* |
| C1 / C1b | The tenant page and the public landing page answer, and the link between them is intact |
| C2 | The security headers are present **and still carry their expected values** |
| C3 | The page is fresh — and its timestamp is not in the *future* (a broken clock would otherwise make staleness undetectable forever) |
| C4 | We are looking at the expected tenant and anchor schema, not some other document |
| C5a | **The published anchor verifies with the same open-source tool auditors are told to use** |
| C5b | **Append-only witness**: the prefix already observed has not been rewritten, and the chain has not shrunk |
| C5c | The human-readable page and the machine-readable anchor agree with each other |
| C6 | The historic anchor URL still resolves and converges with the current one |
| C7 | Sustained degradation (intermittent errors), by rate rather than by consecutive failures |
| C8 | The evidence behind the record has not gone stale, even while the page looks fresh |
| C9 | The TLS certificate is not about to expire |

`state/history.jsonl` is an append-only log of every observation. It is committed
to this repository, so the witness leaves a public, timestamped trail rather than
living only in run logs that expire.

## Notes on the design

**Liveness is not "the chain grows".** New verdicts are only emitted when there
is new evidence, so a flat count is legitimate and may stay flat for days.
Alerting on it would produce false positives, and enough false positives train
people to ignore the alarm — which is how monitoring actually dies. Liveness is
measured by page freshness (C3); the chain checks prove *integrity*, not motion.

**Staleness is measured against the run's scheduled time**, not its execution
time, so platform scheduling delay does not contaminate the measurement.

**The canary checks the reason, not just the outcome.** An early version passed
when the checks were failing merely because an interpreter was missing: a check
that cannot run looked identical to a check in perfect health. Every expectation
now asserts the specific failure it is supposed to observe.

**Timing invariant** — these numbers hold together and must not be changed in
isolation:

```
staleness (90 min) + interval (30 min) + tolerated delay (45 min) <= 3 h
ping period (60 min) + grace (75 min)                             <= 3 h
```

## Running it locally

```sh
cargo install seetrex-verifier --locked --version 0.3.0
VERIFIER_BIN="$HOME/.cargo/bin/seetrex-verifier" bash bin/canary.sh
```

The canary runs entirely offline. The full monitor additionally needs the
environment variables declared at the top of the workflow.

## Scope

This repository observes the **public surface** of the Trust Center. It does not
have, and does not need, any credential or private access to Seetrex systems:
everything it reads is what any auditor can read.
