#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of K9s

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
DEMO_SCRIPT="$SCRIPT_DIR/netpol-demo-workloads.sh"
EXPECT_SCRIPT="$SCRIPT_DIR/k9s-tui-smoke.exp"
PHASES=(preflight ensure-cluster ensure-workloads build-image go-tests tui-tests report)
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$SKILL_DIR/runs/$RUN_ID"
CLUSTER="k9s-netpol"
PREFIX="netpol-demo"
TIMEOUT="180s"
IMAGE_NAME="k9s"
ONLY=""
FROM=""
SKIPS=()
FORCE_WORKLOADS=0
REBUILD=0
BUILT_IMAGE=""
OVERALL_STATUS=0

usage() {
  cat <<USAGE
Usage: $0 [options]

Options:
  --only PHASE          run one phase (preflight, ensure-cluster, ensure-workloads, build-image, go-tests, tui-tests, report)
  --skip PHASE          skip a phase; may be repeated
  --from PHASE          run from PHASE through report
  --force-workloads     repopulate workloads even when --check succeeds
  --rebuild             rebuild the k9s Docker image even when the tree cache matches
  --cluster NAME        kind cluster name (default: $CLUSTER)
  --prefix NAME         demo namespace prefix (default: $PREFIX)
  --timeout DURATION    readiness timeout passed to the demo script (default: $TIMEOUT)
  -h, --help            show this help
USAGE
}

phase_index() {
  local want="$1" i
  for i in "${!PHASES[@]}"; do
    [[ "${PHASES[$i]}" == "$want" ]] && { echo "$i"; return 0; }
  done
  return 1
}

is_skipped() {
  local phase="$1" skip
  # bash 3.2 (the macOS system shell) errors on "${arr[@]}" when the array is
  # empty and `set -u` is active, so expand defensively.
  for skip in ${SKIPS[@]+"${SKIPS[@]}"}; do
    [[ "$skip" == "$phase" ]] && return 0
  done
  return 1
}

should_run() {
  local phase="$1" idx from_idx
  if [[ -n "$ONLY" ]]; then
    [[ "$phase" == "$ONLY" ]]
    return
  fi
  if is_skipped "$phase"; then
    return 1
  fi
  if [[ -n "$FROM" ]]; then
    idx="$(phase_index "$phase")"
    from_idx="$(phase_index "$FROM")"
    (( idx >= from_idx ))
    return
  fi
  return 0
}

require_phase() {
  phase_index "$1" >/dev/null || { echo "unknown phase: $1" >&2; exit 2; }
}

log_path() { echo "$RUN_DIR/$1.log"; }
status_path() { echo "$RUN_DIR/$1.status"; }

record_status() {
  local phase="$1" status="$2"
  printf '%s\n' "$status" >"$(status_path "$phase")"
}

run_phase() {
  local phase="$1" log
  should_run "$phase" || { record_status "$phase" skipped; return 0; }
  [[ "$phase" == report ]] && return 0
  log="$(log_path "$phase")"
  echo "==> phase: $phase (log: $log)"
  set +e
  local func="phase_${phase//-/_}"
  "$func" >"$log" 2>&1
  local rc=$?
  set -e
  if (( rc == 0 )); then
    record_status "$phase" ok
    echo "    ok"
  else
    record_status "$phase" failed
    OVERALL_STATUS=1
    echo "    failed (see $log)" >&2
    if [[ -n "$ONLY" ]]; then
      return "$rc"
    fi
  fi
}

phase_preflight() {
  local cmd
  for cmd in docker kind kubectl go expect; do
    command -v "$cmd" >/dev/null || { echo "$cmd not found in PATH" >&2; return 1; }
    echo "$cmd: $(command -v "$cmd")"
  done
  docker info >/dev/null
  echo "docker daemon: reachable"
}

phase_ensure_cluster() {
  if kind get clusters 2>/dev/null | grep -Fx "$CLUSTER" >/dev/null; then
    echo "kind cluster $CLUSTER exists; reusing"
    mkdir -p "$SKILL_DIR/.kube"
    kind get kubeconfig --name "$CLUSTER" >"$SKILL_DIR/.kube/${CLUSTER}.kubeconfig"
    kind get kubeconfig --name "$CLUSTER" --internal >"$SKILL_DIR/.kube/${CLUSTER}.internal.kubeconfig"
    chmod 600 "$SKILL_DIR/.kube/${CLUSTER}.kubeconfig" "$SKILL_DIR/.kube/${CLUSTER}.internal.kubeconfig"
    kubectl --kubeconfig "$SKILL_DIR/.kube/${CLUSTER}.kubeconfig" wait --for=condition=Ready nodes --all --timeout="$TIMEOUT"
    "$DEMO_SCRIPT" --cluster "$CLUSTER" --prefix "$PREFIX" --timeout "$TIMEOUT" --check >/dev/null || \
      echo "cluster exists but workloads are not fully ready yet"
    return 0
  fi
  echo "kind cluster $CLUSTER not found; bootstrapping via demo script"
  "$DEMO_SCRIPT" --cluster "$CLUSTER" --prefix "$PREFIX" --timeout "$TIMEOUT" --no-wait
}

phase_ensure_workloads() {
  if (( FORCE_WORKLOADS == 0 )) && "$DEMO_SCRIPT" --cluster "$CLUSTER" --prefix "$PREFIX" --timeout "$TIMEOUT" --check; then
    echo "demo workloads already applied and ready; skipping population"
    return 0
  fi
  echo "applying demo workloads"
  "$DEMO_SCRIPT" --cluster "$CLUSTER" --prefix "$PREFIX" --timeout "$TIMEOUT"
  "$DEMO_SCRIPT" --cluster "$CLUSTER" --prefix "$PREFIX" --timeout "$TIMEOUT" --check
}

# EMPTY_SHA256 is the digest of empty input: what shasum returns when the file
# list is empty, i.e. when fingerprinting silently failed.
EMPTY_SHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# tree_hash fingerprints exactly the tracked sources the image is built from.
# It must never fail quietly: a constant hash would match the cache on every run
# and the TUI phase would keep testing a stale binary while reporting success.
tree_hash() {
  (
    cd "$REPO_ROOT" || exit 1
    git ls-files -z -- go.mod go.sum Makefile Dockerfile main.go cmd internal \
      | xargs -0 shasum -a 256 \
      | shasum -a 256 \
      | awk '{print $1}'
  )
}

phase_build_image() {
  local cache_file="$SKILL_DIR/.image-cache" hash cached_hash cached_image output
  hash="$(tree_hash)"
  if [[ -z "$hash" || "$hash" == "$EMPTY_SHA256" ]]; then
    echo "could not fingerprint the source tree; refusing to trust the image cache" >&2
    return 1
  fi
  echo "source fingerprint: $hash"
  if [[ -f "$cache_file" ]]; then
    read -r cached_hash cached_image <"$cache_file" || true
    if (( REBUILD == 0 )) && [[ "$cached_hash" == "$hash" ]] && docker image inspect "$cached_image" >/dev/null 2>&1; then
      BUILT_IMAGE="$cached_image"
      echo "reusing cached image: $BUILT_IMAGE"
      return 0
    fi
  fi
  output="$($REPO_ROOT/scripts/docker-build.sh)"
  printf '%s\n' "$output"
  BUILT_IMAGE="$(printf '%s\n' "$output" | awk '/^==> built image:/ {print $4; exit}')"
  [[ -n "$BUILT_IMAGE" ]] || { echo "failed to parse built image tag" >&2; return 1; }
  printf '%s %s\n' "$hash" "$BUILT_IMAGE" >"$cache_file"
}

phase_go_tests() {
  cd "$REPO_ROOT"
  go test -race ./internal/netpol/... ./internal/view/...
  # internal/ui and internal/model carry pre-existing upstream races in the
  # flash, prompt and log tests, so only the reachability suites are selected
  # here. Run the full packages manually to audit those separately.
  go test -race ./internal/ui/ -run 'Reachability|DirectionPanel|SubjectInfo|SubjectPicker|PrimitiveKind|RuleDetails|Applicability'
  go test -race ./internal/model/ -run 'NetPolGraph|NetworkPolicyGraph'
}

ensure_test_image() {
  if [[ -n "$BUILT_IMAGE" ]]; then
    echo "$BUILT_IMAGE"
    return 0
  fi
  if [[ -f "$SKILL_DIR/.image-cache" ]]; then
    awk '{print $2}' "$SKILL_DIR/.image-cache"
    return 0
  fi
  docker images --format '{{.Repository}}:{{.Tag}}' "$IMAGE_NAME" | sort -V | tail -n1
}

# container_kubeconfig returns a kubeconfig the container can actually use.
# The kind API server certificate is only valid for the control-plane container
# name and localhost, so host.docker.internal fails TLS verification. The
# "internal" kubeconfig points at the control-plane container name instead,
# which resolves - and verifies - from inside the kind Docker network.
container_kubeconfig() {
  local internal_config="$SKILL_DIR/.kube/${CLUSTER}.internal.kubeconfig"
  local container_config="$RUN_DIR/${CLUSTER}.container.kubeconfig"
  mkdir -p "$SKILL_DIR/.kube"
  [[ -f "$internal_config" ]] || kind get kubeconfig --name "$CLUSTER" --internal >"$internal_config"
  cp "$internal_config" "$container_config"
  chmod 600 "$container_config"
  echo "$container_config"
}

# kind_network reports the Docker network hosting the cluster's control plane.
kind_network() {
  local net
  net="$(docker inspect "${CLUSTER}-control-plane" \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null \
    | awk '{print $1}')"
  echo "${net:-kind}"
}

phase_tui_tests() {
  local image kubeconfig network
  image="$(ensure_test_image)"
  [[ -n "$image" ]] || { echo "no k9s image found; run build-image first" >&2; return 1; }
  kubeconfig="$(container_kubeconfig)"
  network="$(kind_network)"
  echo "using image $image on docker network $network"
  echo "probing cluster from the container"
  docker run --rm --network "$network" \
    -e KUBECONFIG=/root/.kube/config -v "$kubeconfig:/root/.kube/config:ro" \
    --entrypoint kubectl "$image" get namespace "$PREFIX-app"
  K9S_IMAGE="$image" \
    KUBECONFIG_MOUNT="$kubeconfig" \
    DOCKER_NETWORK="$network" \
    CLUSTER_PREFIX="$PREFIX" \
    EXPECT_LOG_DIR="$RUN_DIR" \
    "$EXPECT_SCRIPT"
}

phase_report() {
  local phase status failed=0
  echo
  echo "NetworkPolicy graph test run: $RUN_DIR"
  printf '%-18s %s\n' Phase Status
  printf '%-18s %s\n' ----- ------
  for phase in "${PHASES[@]}"; do
    [[ "$phase" == report ]] && continue
    status="not-run"
    [[ -f "$(status_path "$phase")" ]] && status="$(cat "$(status_path "$phase")")"
    printf '%-18s %s\n' "$phase" "$status"
    [[ "$status" == failed ]] && failed=1
  done
  (( failed == 0 ))
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) ONLY="$2"; require_phase "$ONLY"; shift 2 ;;
    --skip) require_phase "$2"; SKIPS+=("$2"); shift 2 ;;
    --from) FROM="$2"; require_phase "$FROM"; shift 2 ;;
    --force-workloads) FORCE_WORKLOADS=1; shift ;;
    --rebuild) REBUILD=1; shift ;;
    --cluster) CLUSTER="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "$RUN_DIR"

for phase in "${PHASES[@]}"; do
  run_phase "$phase"
done

phase_report | tee "$(log_path report)"
(( OVERALL_STATUS == 0 ))
