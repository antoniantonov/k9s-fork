---
name: netpol-graph-testing
description: Test the netpol graph, k9s NetworkPolicy reachability view, netpol e2e tests, and verification of the NetworkPolicy view with kind, demo workloads, Go tests, and TUI smoke tests.
---

# NetworkPolicy graph testing

This skill validates the k9s NetworkPolicy reachability view (`:netpolgraph`, `:npgraph`, `:npg`, Shift-R) against a local kind demo topology.

This is **live-API application/TUI testing**, not packet-delivery testing. The
fixture CRDs do not install Cilium, Istio, or an enforcing dataplane. The
optional conformance lane (`scripts/netpol-conformance.sh`, see below) is the
only place where graph verdicts are compared with real enforcement.

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
`${prefix}-edge-dst`, and `${prefix}-edge-other` scenarios: 21 ready bare pods,
namespace/pod labels (including the Istio mesh-enrollment labels and the stale
sidecar annotation), and 18 policy specifications. `${prefix}-app`,
`${prefix}-edge-src`, and `${prefix}-edge-dst` are labeled
`istio.io/dataplane-mode=ambient`, because AuthorizationPolicy only applies to
mesh workloads. Policy `spec`/`specs` are
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
the merge base of `$DIFF_COVER_BASE` (default `origin/master`, or `master` when
there is no such remote branch) with the current working tree and requires at
least 80% changed-statement coverage overall and in each of
`internal/netpol/policy.go`, `policy_cilium.go`, `policy_istio.go`, `mesh.go`,
and `selection.go`. A stale local `master` is never the default, because it
would attribute upstream merges to the branch. Use `--only PHASE`, `--skip PHASE`, `--from PHASE`,
`--rebuild`, `--clean-image`/`--no-image-cache`, `--image REF`, and
`--force-workloads` as needed.

Logs land under `.github/skills/netpol-graph-testing/runs/<timestamp>/`, with one log per phase plus the expect session log. `image.ref`, `image.id`, and `image.source` record the resolved tag/reference, immutable image ID, and selection path used by TUI tests. A clean build never falls back to `.image-cache` or another local image. Failures should be read from the named phase log; TUI stress timeouts send `SIGQUIT` to the container to capture goroutines.

Run directories include the process ID to prevent concurrent invocations from
overwriting one another. Cached builds fingerprint untracked build sources as
well as tracked files; fingerprint failures cannot silently reuse an image.
Finish all source edits before invoking the runner or workload entry point,
and keep those scripts unchanged until the invocation exits. A shell may read
later parts of its script while running; a concurrent rewrite can interrupt
population even when the final file passes `bash -n`.

## Complete-data and uncertainty suites

`tui-tests` runs **77 known-fixture cases**, then **2 identity cases**, then
**2 unsupported-Cilium cases**, always using the same immutable image ID.
New assertions reconstruct a fresh terminal repaint and compare the subject,
direction, exact peer row, state and complete protocol/port set. Navigation
checks bind the selected rule to its full policy type, action, API version,
resource view and YAML identity.
All snapshot, regex, navigation and command-prompt waits use one shared reader.
It drains and requests a fresh repaint once, then updates terminal cells
incrementally, retaining split CSI/OSC sequences across reads. Re-parsing an
ever-growing ANSI prefix on every short PTY read can starve input before a
deadline even when complete frames are already waiting in the pipe. The reader
requires the final-size bottom breadcrumb before accepting a frame; a top-only
header or short quiet interval is not completion. Grouped assertions inspect
one complete frame rather than requesting a redraw for each text fragment.
Read timeouts start after the separately bounded drain/resize preparation;
otherwise a one-second hint check expires before it starts reading. A missing
mode frame is a setup failure, never a reason to blindly send the mode-toggle
key. Failure diagnostics include preparation time, read budget and byte counts.
Applicability assertions wait up to 20 seconds for the requested heading,
exact peer row and closing table border. Fragmented terminal chunks accumulate
within that one fresh repaint and share its deadline; they are not discarded
by another drain/repaint. Only surface completeness is polled. State, flags and
ports are then checked exactly, without retrying incorrect semantic values.

Each fresh process first waits for the default NPG subject and its ready
workload rows. Opening an edge subject then waits for the command prompt to
appear, sends the command once, and waits for the exact one-pod subject, its
Running/ready workload row and a closed prompt before mode, direction or search
keys. Waits are bounded; genuine `Waiting for ...` and `workloads loading...`
frames are not ready, but expected Partial Data is. A failed setup stops further
graph input and still produces explicit failed verdicts instead of cascading
shortcuts into an unfinished prompt.

Rules are headerless three-column blocks, unlike the applicability table.
Their declared port text is checked exactly, including ordering and separate
entries such as `TCP/8080, TCP/8081`; it is not merged into a range. Effective
permissions are checked separately and keep their exact expected port text.

Applicability booleans are literal `true`/`false`, not `Yes`/`No`. Selected
allowed rows are `true`/`true`; matched but disjoint or denied rows are
`true`/`false`; unmatched selected rules are `false`/`false`. The selected CCNP
deny remains Disallowed with `no ports` even when another port survives in the
effective result. Zero-pair rows use `n/a` for Peer, Opposite and Ports.
Rule names display the policy reference, then the Cilium spec entry when the
resource has several `spec`/`specs` entries, then `deny` for deny rules, then
`#<rule index>`: the first CNP allow in `specs[0]` is `…/cnp-source specs[0] #0`
and the first deny in `specs[1]` is `…/cnp-source specs[1] deny #0`. Rule
Details show the entry on the rule index line, `Rule index: 0 in specs[1]
(spec index 1)`, for Cilium rules only (the detail pane is short, so no line is
added); native and Istio rules show a plain `Rule index: 0`, and no
`Spec index:` label exists. The identity note sits below the rule YAML, so the
identity case scrolls Rule Details from the top until it has seen
`State: Allowed (Allowed)` and the note, rejecting any `Partial Data` or
`Warnings:` on the way.

The CIDR control checks **both** rows from `edge-src/cidr-client` egress.
The partly denied `203.0.113.0/24` is **Unknown**, while the fully denied
`203.0.113.128/25` is **Disallowed**. Both have exact `no ports`,
Peer `true` and Opposite `n/a`. A narrower deny is address-overlap uncertainty,
not snapshot-wide Partial Data and not uniform Disallowed for the broad range.

Known-state Istio fixtures use identity-free port-only ALLOW/DENY rules. They
also prove that a source-local ingress AuthorizationPolicy does not become a
source egress policy. Effective port text is compared exactly:
`SCTP/9000, TCP/8080, UDP/5353` after the TCP deny, and `SCTP/9000, UDP/5353`
for the empty ALLOW control. Mesh enrollment is covered by `authz-unenrolled`
(`istio.io/dataplane-mode=none`, so its allow-nothing policy is not enforced:
`Allowed SCTP/9000, TCP/8080, TCP/8081, UDP/5353`) and `authz-unknown` (a
`sidecar.istio.io/status` annotation without an `istio-proxy` container, so
enrollment is unknown: `Partial Data SCTP/9000, TCP/8080, UDP/5353`). The
`istio-authorization-default-deny-row` case checks that an Istio ALLOW adds a
separate `authorization default-deny (TCP) #-1` synthetic row next to the
network `default-deny #-1` row.

Uncertainty is **scoped to the pairs it can affect**. The ordinary topology
contains `cnp-l7`, an L7 rule on `l7-server` that only matches the `control`
pod: `control → l7-server` is `Partial Data TCP/8080`, while the unmatched
`authz-client → l7-server` pair stays a definitive `Disallowed`. Pods with
Cilium policies see `hostNetwork` system pods as `Partial Data`
(`cilium-hostnetwork-peer-partial-data`, matched by the `kube-proxy-` prefix),
while the same peer of a native/Istio-only subject stays definitive
(`hostnetwork-peer-native-control`). Every known case that expects a complete
result asserts that no `Partial Data` cell is on screen.

The identity and unsupported probes stay opt-in so their suites run against a
fixed topology. For each final probe suite the
runner checks that known fixtures are clean, checks the probe before applying
it, launches a fresh TUI process, and removes only the exact policy carrying
that run's ownership ID in an EXIT/signal cleanup handler. The normal topology
is rechecked even after a failing TUI run or failed deletion. A failed cleanup
fails validation; a subsequent suite cannot populate over an unclean topology.
The unsupported probe checks the exact per-rule diagnostic
`CiliumNetworkPolicy <namespace>/<probe>: egress allow rule 0: toFQDNs requires
live DNS resolution` in **Effective Details**, scrolling that pane from the top
when necessary (warnings are sorted, so it precedes the `hostNetwork` peer
warnings). Partial state is confirmed by the subject's `PARTIAL DATA` badge and
applicability `Partial Data` cells, not an invented mixed-case label in the
lowercase details summary. Disabled empty rules may be omitted from the Rules
panel, so this case does not invent a selectable raw rule. While the probe is
applied, `unsupported-scoped-egress-control` proves scoping: `cnp-client →
cnp-server` stays `Allowed TCP/8081` with no Partial Data. The identity probe
(`source.namespaces` on `authz-identity`) is evaluated from workload metadata
because both pods are in the mesh: the path is a definitive
`Allowed SCTP/9000, TCP/8080, TCP/8081, UDP/5353`, and the selected rule's
details carry the `mesh mTLS` approximation note with `State: Allowed`. The
known Cilium navigation cases cover its API version and YAML.

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
=== 81 case(s), 0 failure(s) ===
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
aggregate and the per-file thresholds for the policy normalization files
(`policy.go`, `policy_cilium.go`, `policy_istio.go`, `mesh.go`,
`selection.go`) all reach 80%.

The denominator includes committed branch changes and staged, unstaged and
untracked production Go files. Changed executable functions missing from the
profile fail the gate rather than disappearing from it; declaration-only code
does not invent executable statements. Profile paths are matched within the
actual module, not by ambiguous basename suffixes. These are Go **statement**
coverage gates, not independent branch-coverage instrumentation.

The helper's Go tests also exercise shell stubs, the 21-pod/18-policy fixture
inventory and its mesh labels, Tcl compilation, fresh-screen parsing, both CIDR
rows, spec-entry and action rule labels, per-layer synthetic rows, prefix-matched
hostNetwork peer rows, headerless declared-rule rows, delayed startup and
command-prompt closure, fragmented repaint completion, an exact live
unsupported-policy screen fixture with negative diagnostic controls, and verdict
accounting without contacting Docker or Kubernetes. A real local PTY stub
exercises delayed resource/YAML return and command-prompt tails, enforcing one
repaint per operation and no whole-prefix re-parsing. Probe cleanup is tested
after success, failed application, failed
Expect, termination, failed deletion and failed topology restoration, for both
probe types. A stubbed full population invocation must reach its final summary.

```bash
for script in scripts/netpol-demo-workloads.sh \
  .github/skills/netpol-graph-testing/scripts/*.sh; do
  bash -n "$script" || exit
done
EXPECT_SYNTAX_CHECK=1 expect .github/skills/netpol-graph-testing/scripts/k9s-tui-smoke.exp
EXPECT_CASE_MANIFEST=1 expect .github/skills/netpol-graph-testing/scripts/k9s-tui-smoke.exp
mkdir -p .github/skills/netpol-graph-testing/runs/helper-check
TMPDIR="$PWD/.github/skills/netpol-graph-testing/runs/helper-check" \
GOTMPDIR="$PWD/.github/skills/netpol-graph-testing/runs/helper-check" \
  go test ./.github/skills/netpol-graph-testing/diffcover -count=1
```

## Optional conformance lane

`scripts/netpol-conformance.sh` compares graph verdicts with real enforcement.
It creates a separate kind cluster (default `k9s-netpol-conformance`, never the
demo cluster) without the default CNI, installs Cilium and Istio (sidecar mode)
with Helm, deploys a small workload set with Services, applies Kubernetes,
Cilium, and Istio policies, and probes HTTP requests through the Service
ClusterIPs until two rounds agree. Sidecars only present an mTLS identity to
destinations they know as mesh endpoints, so bare pod IPs are not probed. The
same live objects are then evaluated by
`go test -tags conformance ./internal/netpol/conformance`, which fails on any
definitive graph verdict that disagrees with a probe (Partial Data verdicts are
reported but not compared). It covers Cilium allow/deny, Istio namespace
identities from mesh and non-mesh sources, an AuthorizationPolicy on a non-mesh
pod that is not enforced, and native egress. The lane needs internet access for
the charts and images and is not part of `run-tests.sh`:

```bash
scripts/netpol-conformance.sh            # create, test, keep the cluster
scripts/netpol-conformance.sh --delete   # remove the conformance cluster
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
