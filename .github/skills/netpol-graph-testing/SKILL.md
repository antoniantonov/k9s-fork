---
name: netpol-graph-testing
description: Test the netpol graph, k9s NetworkPolicy reachability view, netpol e2e tests, and verification of the NetworkPolicy view with kind, demo workloads, Go tests, and TUI smoke tests.
---

# NetworkPolicy graph testing

This skill validates the k9s NetworkPolicy reachability view (`:netpolgraph`, `:npgraph`, `:npg`, Shift-R) against a local kind demo topology.

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

# TUI-only validation against one exact local image
.github/skills/netpol-graph-testing/scripts/run-tests.sh --only tui-tests --image sha256:<image-id>
```

Phases: `preflight`, `ensure-cluster`, `ensure-workloads`, `go-tests`, `build-image`, `tui-tests`, `report`. Use `--only PHASE`, `--skip PHASE`, `--from PHASE`, `--rebuild`, `--clean-image`/`--no-image-cache`, `--image REF`, and `--force-workloads` as needed.

Logs land under `.github/skills/netpol-graph-testing/runs/<timestamp>/`, with one log per phase plus the expect session log. `image.ref`, `image.id`, and `image.source` record the resolved tag/reference, immutable image ID, and selection path used by TUI tests. A clean build never falls back to `.image-cache` or another local image. Failures should be read from the named phase log; TUI stress timeouts send `SIGQUIT` to the container to capture goroutines.

## Reading the results

The `tui-tests` log ends with an authoritative summary block. Per-case `PASS`/
`FAIL` lines printed mid-run interleave with the TUI's own redraw bytes, so
parse this block rather than those lines:

```
=== smoke case summary ===
  PASS   launch-npg-view
  ...
=== 21 case(s), 0 failure(s) ===
```

Every started case is guaranteed to record a verdict; a case that falls through
its assertions without one is reported as a failure rather than silently
vanishing.

To read a session visually, strip the terminal escapes:

```bash
perl -pe 's/\e\[[0-9;?]*[a-zA-Z]//g; s/\e[()][AB012]//g; s/\r/\n/g' \
  runs/<timestamp>/k9s-tui-smoke.session.log
```

## Scope of the Go test phase

`go-tests` first clears the build and test caches and runs the default
`go test ./...` suite. It then runs `-race` over `./internal/netpol/...` and
`./internal/view/...` in full, but only the reachability suites in
`./internal/ui/` and `./internal/model/`. Those two packages carry pre-existing
upstream races in `TestFlash`, `TestFlashBurst`, `TestShowPrompt` and
`TestUpdateLogs`, which fail at the base commit and are unrelated to this view.

## Cleanup

```bash
.github/skills/netpol-graph-testing/scripts/netpol-demo-workloads.sh --delete
.github/skills/netpol-graph-testing/scripts/netpol-demo-workloads.sh --delete-cluster
```
