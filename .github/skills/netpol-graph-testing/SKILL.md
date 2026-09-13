---
name: netpol-graph-testing
description: Test the netpol graph, k9s NetworkPolicy reachability view, netpol e2e tests, and verification of the NetworkPolicy view with kind, demo workloads, Go tests, and TUI smoke tests.
---

# NetworkPolicy graph testing

This skill validates the k9s NetworkPolicy reachability view (`:netpolgraph`, `:npgraph`, `:npg`, Shift-R) against a local kind demo topology.

This is **live-API application/TUI testing**, not packet-delivery testing. The
fixture CRDs do not install Cilium, Istio, or an enforcing dataplane.

## Prerequisites

`docker`, `kind`, `kubectl`, `go`, and `expect` must be on `PATH`; Docker must be running.

The TUI phase runs the container on the kind Docker network with the cluster's
`--internal` kubeconfig. This is deliberate and works the same on macOS and
Linux: the kind API server certificate is only valid for the control-plane
container name and `localhost`, so reaching it via a published port from inside
a container fails TLS verification.

## Required workflow

Before populating workloads, agents must run:

```bash
.github/skills/netpol-graph-testing/scripts/netpol-demo-workloads.sh --check
```

Only run the population path when `--check` fails, unless `--force-workloads` is explicitly needed.

The check includes the original topology and isolated `${prefix}-edge-src`,
`${prefix}-edge-dst`, and `${prefix}-edge-other` scenarios: 18 ready bare pods,
namespace/pod labels, and 15 policy specifications. Policy `spec`/`specs` are
compared with the desired manifests using a **client-only dry run**; merely
retaining an object name or ownership label cannot hide drift. It also rejects
leftover uncertainty probes. Existing native/custom-only demo subjects are
unchanged. Prefixes are DNS labels, at most 52 characters.

## Commands

```bash
# Verify tools only
.github/skills/netpol-graph-testing/scripts/run-tests.sh --only preflight

# Ensure the live demo topology exists; check first, populate only if needed
.github/skills/netpol-graph-testing/scripts/run-tests.sh --only ensure-workloads

# Run from image build through report
.github/skills/netpol-graph-testing/scripts/run-tests.sh --from build-image

# Full run
.github/skills/netpol-graph-testing/scripts/run-tests.sh

# Full validation with an uncached, uniquely tagged image
.github/skills/netpol-graph-testing/scripts/run-tests.sh --clean-image

# All TUI suites against one exact local image (includes owned probe lifecycle)
.github/skills/netpol-graph-testing/scripts/run-tests.sh --only tui-tests --image sha256:<image-id>

# Pure syntax/inventory checks: no Docker or Kubernetes access
EXPECT_SYNTAX_CHECK=1 expect .github/skills/netpol-graph-testing/scripts/k9s-tui-smoke.exp
EXPECT_CASE_MANIFEST=1 expect .github/skills/netpol-graph-testing/scripts/k9s-tui-smoke.exp
```

Syntax mode compiles both complete Tcl files and their procedure bodies without
executing TUI commands; balanced but invalid late-file commands also fail.

Phases: `preflight`, `ensure-cluster`, `ensure-workloads`, `go-tests`,
`coverage`, `build-image`, `tui-tests`, `report`. The coverage phase compares
the merge base of `${DIFF_COVER_BASE:-master}` with the current working tree and
requires at least 80% changed-statement coverage both overall and in
`internal/netpol/policy.go`. Use `--only PHASE`, `--skip PHASE`, `--from PHASE`,
`--rebuild`, `--clean-image`/`--no-image-cache`, `--image REF`, and
`--force-workloads` as needed.

Logs land under `.github/skills/netpol-graph-testing/runs/<timestamp>/`, with one log per phase plus the expect session log. `image.ref`, `image.id`, and `image.source` record the resolved tag/reference, immutable image ID, and selection path used by TUI tests. A clean build never falls back to `.image-cache` or another local image. Failures should be read from the named phase log; TUI stress timeouts send `SIGQUIT` to the container to capture goroutines.

Run directories include the process ID to prevent concurrent invocations from
overwriting one another. Cached builds fingerprint untracked build sources as
well as tracked files; fingerprint failures cannot silently reuse an image.

## Complete-data and uncertainty suites

`tui-tests` runs **66 known-fixture cases**, then **2 identity cases**, then
**2 unsupported-Cilium cases**, always using the same immutable image ID.
New assertions reconstruct a fresh terminal repaint and compare the subject,
direction, exact peer row, state and complete protocol/port set. Navigation
checks bind the selected rule to its full policy type, action, API version,
resource view and YAML identity.

Istio `source.namespaces` is certificate/mTLS-derived and therefore uncertain
from Kubernetes objects alone. Known-state fixtures use identity-free port-only
ALLOW/DENY rules. They also prove that a source-local ingress AuthorizationPolicy
does not become a source egress policy.

Normalization uncertainty is **snapshot-wide**. The identity and unsupported
policies are never part of ordinary population. For each final probe suite the
runner checks that known fixtures are clean, checks the probe before applying
it, launches a fresh TUI process, and removes only the exact policy carrying
that run's ownership ID in an EXIT/signal cleanup handler. The normal topology
is rechecked even after a failing TUI run or failed deletion. A failed cleanup
fails validation; a subsequent suite cannot populate over an unclean topology.

For controlled diagnosis, the demo entry point exposes the same probe flags:

```bash
DEMO=.github/skills/netpol-graph-testing/scripts/netpol-demo-workloads.sh
PROBE_ID="manual-$(date +%Y%m%d-%H%M%S)-$$"
"$DEMO" --check
if ! "$DEMO" --probe identity --probe-id "$PROBE_ID" --check; then
  "$DEMO" --probe identity --probe-id "$PROBE_ID"
fi
# Diagnose this probe only; always perform both cleanup commands afterward.
"$DEMO" --probe identity --probe-id "$PROBE_ID" --delete
"$DEMO" --check
```

Use `--probe unsupported` for the Cilium dynamic-peer fixture. Prefer the full
runner for automated use: it supplies cleanup even on failure. Expect itself
does not mutate the cluster. Direct probe-only Expect invocations require
`SMOKE_SUITE=identity` or `unsupported` and the matching `PROBE_ID`.

## Reading the results

The `tui-tests` log ends with a combined authoritative summary block. Per-case `PASS`/
`FAIL` lines printed mid-run interleave with the TUI's own redraw bytes, so
parse this block rather than those lines:

```
=== authoritative combined smoke summary ===
  PASS   known/launch-npg-view
  ...
=== 70 case(s), 0 failure(s) ===
```

Every declared case must have exactly one verdict. Missing, duplicate,
unexpected, failed and fall-through cases fail validation. The runner compares
`smoke-<suite>.verdicts` against the pure `EXPECT_CASE_MANIFEST=1` inventory and
retains `smoke.expected` and `smoke.verdicts`. A process abort cannot silently
remove cases. Per-suite terminal logs are `k9s-tui-smoke-<suite>.session.log`.

To read a session visually, strip the terminal escapes:

```bash
perl -pe 's/\e\[[0-9;?]*[a-zA-Z]//g; s/\e[()][AB012]//g; s/\r/\n/g' \
  runs/<timestamp>/k9s-tui-smoke-known.session.log
```

## Scope of the Go test phase

`go-tests` first clears the build and test caches and runs the default
`go test ./...` suite. It then runs `-race` over `./internal/netpol/...` and
`./internal/view/...` in full, but only the reachability suites in
`./internal/ui/` and `./internal/model/`. Those two packages carry pre-existing
upstream races in `TestFlash`, `TestFlashBurst`, `TestShowPrompt` and
`TestUpdateLogs`, which fail at the base commit and are unrelated to this view.

The `coverage` phase reruns the changed NPG packages with a combined cover
profile, tests the repository-local diff coverage parser, and fails unless the
aggregate and `internal/netpol/policy.go` changed-statement thresholds both
reach 80%.

The denominator includes committed branch changes and staged, unstaged and
untracked production Go files. Changed executable functions missing from the
profile fail the gate rather than disappearing from it; declaration-only code
does not invent executable statements. Profile paths are matched within the
actual module, not by ambiguous basename suffixes. These are Go **statement**
coverage gates, not independent branch-coverage instrumentation.

The helper's Go tests also exercise shell stubs, fixture contracts, Tcl
compilation, fresh-screen parsing and verdict accounting without contacting
Docker or Kubernetes:

```bash
mkdir -p .github/skills/netpol-graph-testing/runs/helper-check
TMPDIR="$PWD/.github/skills/netpol-graph-testing/runs/helper-check" \
GOTMPDIR="$PWD/.github/skills/netpol-graph-testing/runs/helper-check" \
  go test ./.github/skills/netpol-graph-testing/diffcover -count=1
```

## Cleanup

```bash
.github/skills/netpol-graph-testing/scripts/netpol-demo-workloads.sh --delete
.github/skills/netpol-graph-testing/scripts/netpol-demo-workloads.sh --delete-cluster
```

Ordinary `--delete` preserves shared CRDs and never bootstraps a cluster just
to delete fixtures. `--check`/`--status` cannot be combined with either deletion
mode. Full fixture/cluster deletion is not part of validation: retain reusable
demo namespaces and remove only the run-owned probe policies automatically.
