// External waker for this monitor — deployed as a Cloudflare Worker with a
// `20,50 * * * *` cron trigger (the same grid as the native schedule below,
// which stays on as a backup).
//
// WHY IT EXISTS
// GitHub Actions' cron is best-effort and measurably degraded on this repo:
// 4-5 of the 48 daily windows fired over 2026-07-21..26 (see `missed_windows`
// in state/history.jsonl). A monitor whose clock skips 90% of its beats cannot
// hold the "a human learns within 3 hours" invariant, and the resulting
// dead-man noise is what killed layer 2 by alarm fatigue. The clock therefore
// lives on a scheduler that honors it; GitHub only runs the checks.
//
// FAILURE MODE
// If THIS worker dies, dispatches stop and pings collapse to the native
// cadence -> the third-party dead-man fires: the waker's failure becomes an
// alert, never silence.
//
// SECRETS
// `GH_PAT` (Worker secret): fine-grained token, repo `seetrex-hq/trust-monitor`
// only, permission Actions: read+write, nothing else. Rotation is recorded in
// the F1 provision runbook. This file is the public record of the waker's
// logic; the deployed copy lives in the Cloudflare dashboard.
export default {
  async scheduled(event, env, ctx) {
    const res = await fetch(
      "https://api.github.com/repos/seetrex-hq/trust-monitor/actions/workflows/trust-monitor.yml/dispatches",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.GH_PAT}`,
          "Accept": "application/vnd.github+json",
          "User-Agent": "seetrex-trust-monitor-waker",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        body: JSON.stringify({ ref: "main" }),
      },
    );
    if (!res.ok) {
      // Sustained failure is covered by the dead-man; this log is for the
      // human who comes to diagnose it.
      console.log(`dispatch failed: ${res.status} ${await res.text()}`);
    }
  },
};
