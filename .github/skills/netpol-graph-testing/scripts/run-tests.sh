#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of K9s

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
DEMO_SCRIPT="$SCRIPT_DIR/netpol-demo-workloads.sh"
EXPECT_SCRIPT="$SCRIPT_DIR/k9s-tui-smoke.exp"
PHASES=(preflight ensure-cluster ensure-workloads go-tests build-image tui-tests report)
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$SKILL_DIR/runs/$RUN_ID"
CLUSTER="k9s-netpol"
PREFIX="netpol-demo"
TIMEOUT="180s"
IMAGE_NAME="k9s"
REQUESTED_IMAGE=""
ONLY=""
FROM=""
SKIPS=()
FORCE_WORKLOADS=0
REBUILD=0
CLEAN_IMAGE=0
BUILD_ATTEMPTED=0
BUILT_IMAGE_TAG=""
BUILT_IMAGE_ID=""
TEST_IMAGE_TAG=""
TEST_IMAGE_ID=""
OVERALL_STATUS=0

usage() {
  cat <<USAGE
Usage: $0 [options]

Options:
  --only PHASE          run one phase (preflight, ensure-cluster, ensure-workloads, go-tests, build-image, tui-tests, report)
  --skip PHASE          skip a phase; may be repeated
  --from PHASE          run from PHASE through report
  --force-workloads     repopulate workloads even when --check succeeds
  --rebuild             rebuild the k9s Docker image even when the tree cache matches
  --clean-image         build a unique image with docker build --pull --no-cache
  --no-image-cache      alias for --clean-image
  --image REF           use this exact local image for TUI tests; build-image must be skipped
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
image_path() { echo "$RUN_DIR/image.$1"; }

record_status() {
  local phase="$1" status="$2"
  printf '%s\n' "$status" >"$(status_path "$phase")"
}

record_image() {
  local source="$1" tag="$2" id="$3"
  printf '%s\n' "$source" >"$(image_path source)"
  printf '%s\n' "$tag" >"$(image_path ref)"
  printf '%s\n' "$id" >"$(image_path id)"
  echo "image source: $source"
  echo "image ref: $tag"
  echo "immutable image ID: $id"
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
  fi
  return 0
}

phase_preflight() {
  local cmd
  for cmd in docker kind kubectl go expect; do
    command -v "$cmd" >/dev/null || { echo "$cmd not found in PATH" >&2; return 1; }
    echo "$cmd: $(command -v "$cmd")"
  done
  docker info >/dev/null || {
    echo "cannot reach the Docker daemon" >&2
    return 1
  }
  echo "docker daemon: reachable"
}

check_workloads() {
  "$DEMO_SCRIPT" --cluster "$CLUSTER" --prefix "$PREFIX" --timeout "$TIMEOUT" --check
}

phase_ensure_cluster() {
  local topology_ready=0
  echo "checking demo topology before any cluster bootstrap or workload population"
  if check_workloads; then
    topology_ready=1
  else
    echo "demo topology precheck did not pass"
  fi

  if kind get clusters 2>/dev/null | grep -Fx "$CLUSTER" >/dev/null; then
    echo "kind cluster $CLUSTER exists; reusing"
    mkdir -p "$SKILL_DIR/.kube"
    kind get kubeconfig --name "$CLUSTER" >"$SKILL_DIR/.kube/${CLUSTER}.kubeconfig" || return 1
    kind get kubeconfig --name "$CLUSTER" --internal >"$SKILL_DIR/.kube/${CLUSTER}.internal.kubeconfig" || return 1
    chmod 600 "$SKILL_DIR/.kube/${CLUSTER}.kubeconfig" "$SKILL_DIR/.kube/${CLUSTER}.internal.kubeconfig"
    kubectl --kubeconfig "$SKILL_DIR/.kube/${CLUSTER}.kubeconfig" wait --for=condition=Ready nodes --all --timeout="$TIMEOUT" || return 1
    if (( topology_ready == 0 )); then
      check_workloads >/dev/null || echo "cluster exists but workloads are not fully ready yet"
    fi
    return 0
  fi
  echo "kind cluster $CLUSTER not found; precheck completed, bootstrapping via demo script"
  "$DEMO_SCRIPT" --cluster "$CLUSTER" --prefix "$PREFIX" --timeout "$TIMEOUT" --no-wait
}

phase_ensure_workloads() {
  local topology_ready=0
  if check_workloads; then
    topology_ready=1
  fi
  if (( FORCE_WORKLOADS == 0 && topology_ready == 1 )); then
    echo "demo workloads already applied and ready; skipping population"
    return 0
  fi
  if (( FORCE_WORKLOADS == 1 )); then
    echo "workload precheck completed; forcing demo workload population"
  fi
  echo "applying demo workloads"
  "$DEMO_SCRIPT" --cluster "$CLUSTER" --prefix "$PREFIX" --timeout "$TIMEOUT" || return 1
  check_workloads
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
  local cache_file="$SKILL_DIR/.image-cache"
  local hash cached_hash cached_image cached_id current_id output clean_tag
  BUILD_ATTEMPTED=1

  if (( CLEAN_IMAGE == 1 )); then
    clean_tag="${IMAGE_NAME}:netpol-clean-${RUN_ID}-$$"
    echo "building unique clean image: $clean_tag"
    (
      cd "$REPO_ROOT"
      docker build --pull --no-cache -t "$clean_tag" .
    ) || return 1
    current_id="$(docker image inspect --format '{{.Id}}' "$clean_tag")" || return 1
    [[ "$current_id" == sha256:* ]] || {
      echo "docker returned an invalid image ID for $clean_tag: $current_id" >&2
      return 1
    }
    BUILT_IMAGE_TAG="$clean_tag"
    BUILT_IMAGE_ID="$current_id"
    record_image clean-build "$BUILT_IMAGE_TAG" "$BUILT_IMAGE_ID"
    return 0
  fi

  hash="$(tree_hash)"
  if [[ -z "$hash" || "$hash" == "$EMPTY_SHA256" ]]; then
    echo "could not fingerprint the source tree; refusing to trust the image cache" >&2
    return 1
  fi
  echo "source fingerprint: $hash"
  if [[ -f "$cache_file" ]]; then
    read -r cached_hash cached_image cached_id <"$cache_file" || true
    if (( REBUILD == 0 )) && [[ "$cached_hash" == "$hash" ]]; then
      current_id="$(docker image inspect --format '{{.Id}}' "$cached_image" 2>/dev/null || true)"
      if [[ "$current_id" == sha256:* && ( -z "$cached_id" || "$cached_id" == "$current_id" ) ]]; then
        BUILT_IMAGE_TAG="$cached_image"
        BUILT_IMAGE_ID="$current_id"
        echo "reusing cached image: $BUILT_IMAGE_TAG"
        record_image tree-cache "$BUILT_IMAGE_TAG" "$BUILT_IMAGE_ID"
        return 0
      fi
    fi
  fi
  output="$("$REPO_ROOT/scripts/docker-build-and-run.sh" --build-only)" || return 1
  printf '%s\n' "$output"
  BUILT_IMAGE_TAG="$(printf '%s\n' "$output" | awk '/^==> built image:/ {print $4; exit}')"
  [[ -n "$BUILT_IMAGE_TAG" ]] || { echo "failed to parse built image tag" >&2; return 1; }
  BUILT_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$BUILT_IMAGE_TAG")" || return 1
  [[ "$BUILT_IMAGE_ID" == sha256:* ]] || {
    echo "docker returned an invalid image ID for $BUILT_IMAGE_TAG: $BUILT_IMAGE_ID" >&2
    return 1
  }
  printf '%s %s %s\n' "$hash" "$BUILT_IMAGE_TAG" "$BUILT_IMAGE_ID" >"$cache_file"
  record_image build "$BUILT_IMAGE_TAG" "$BUILT_IMAGE_ID"
}

phase_go_tests() {
  cd "$REPO_ROOT"
  go clean -cache -testcache || return 1
  go test ./... || return 1
  go test -race ./internal/netpol/... ./internal/view/... || return 1
  # internal/ui and internal/model carry pre-existing upstream races in the
  # flash, prompt and log tests, so only the reachability suites are selected
  # here. Run the full packages manually to audit those separately.
  go test -race ./internal/ui/ -run 'Reachability|DirectionPanel|SubjectInfo|SubjectPicker|PrimitiveKind|RuleDetails|Applicability' || return 1
  go test -race ./internal/model/ -run 'NetPolGraph|NetworkPolicyGraph' || return 1
}

resolve_test_image() {
  local ref id
  if [[ -n "$REQUESTED_IMAGE" ]]; then
    ref="$REQUESTED_IMAGE"
    id="$(docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true)"
    [[ "$id" == sha256:* ]] || {
      echo "requested image is not available locally: $ref" >&2
      return 1
    }
    TEST_IMAGE_TAG="$ref"
    TEST_IMAGE_ID="$id"
    record_image explicit "$TEST_IMAGE_TAG" "$TEST_IMAGE_ID"
    return 0
  fi

  if [[ -n "$BUILT_IMAGE_ID" ]]; then
    docker image inspect "$BUILT_IMAGE_ID" >/dev/null 2>&1 || {
      echo "built image disappeared before TUI tests: $BUILT_IMAGE_ID" >&2
      return 1
    }
    TEST_IMAGE_TAG="$BUILT_IMAGE_TAG"
    TEST_IMAGE_ID="$BUILT_IMAGE_ID"
    return 0
  fi

  if (( BUILD_ATTEMPTED == 1 )); then
    echo "build-image did not produce an image; refusing .image-cache or local-image fallback" >&2
    return 1
  fi

  if [[ -f "$SKILL_DIR/.image-cache" ]]; then
    ref="$(awk '{print $2}' "$SKILL_DIR/.image-cache")"
    id="$(docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true)"
    if [[ "$id" == sha256:* ]]; then
      TEST_IMAGE_TAG="$ref"
      TEST_IMAGE_ID="$id"
      record_image cache-fallback "$TEST_IMAGE_TAG" "$TEST_IMAGE_ID"
      return 0
    fi
  fi

  ref="$(docker images --format '{{.Repository}}:{{.Tag}}' "$IMAGE_NAME" | sort -V | tail -n1)"
  [[ -n "$ref" ]] || {
    echo "no k9s image found; run build-image first or pass --image REF" >&2
    return 1
  }
  id="$(docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true)"
  [[ "$id" == sha256:* ]] || {
    echo "could not resolve local image: $ref" >&2
    return 1
  }
  TEST_IMAGE_TAG="$ref"
  TEST_IMAGE_ID="$id"
  record_image local-fallback "$TEST_IMAGE_TAG" "$TEST_IMAGE_ID"
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
  resolve_test_image || return 1
  image="$TEST_IMAGE_ID"
  kubeconfig="$(container_kubeconfig)" || return 1
  network="$(kind_network)"
  echo "using exact image $image (ref: $TEST_IMAGE_TAG) on docker network $network"
  echo "probing cluster from the container"
  docker run --rm --network "$network" \
    -e KUBECONFIG=/root/.kube/config -v "$kubeconfig:/root/.kube/config:ro" \
    --entrypoint kubectl "$image" get namespace "$PREFIX-app" || return 1
  K9S_IMAGE="$image" \
    KUBECONFIG_MOUNT="$kubeconfig" \
    DOCKER_NETWORK="$network" \
    CLUSTER_PREFIX="$PREFIX" \
    EXPECT_LOG_DIR="$RUN_DIR" \
    "$EXPECT_SCRIPT"
}

phase_report() {
  local phase status failed=0 image_source image_ref image_id
  echo
  echo "NetworkPolicy graph test run: $RUN_DIR"
  if [[ -f "$(image_path id)" ]]; then
    image_source="$(cat "$(image_path source)")"
    image_ref="$(cat "$(image_path ref)")"
    image_id="$(cat "$(image_path id)")"
    echo "Image: $image_ref"
    echo "Image ID: $image_id ($image_source)"
  fi
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
    --clean-image|--no-image-cache) CLEAN_IMAGE=1; shift ;;
    --image) REQUESTED_IMAGE="$2"; shift 2 ;;
    --cluster) CLUSTER="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -n "$REQUESTED_IMAGE" ]] && should_run build-image; then
  echo "--image requires build-image to be skipped (for example: --only tui-tests --image REF)" >&2
  exit 2
fi
if [[ -n "$REQUESTED_IMAGE" ]] && ! should_run tui-tests; then
  echo "--image requires tui-tests to run" >&2
  exit 2
fi
if (( CLEAN_IMAGE == 1 )) && ! should_run build-image; then
  echo "--clean-image requires build-image to run" >&2
  exit 2
fi

mkdir -p "$RUN_DIR"

for phase in "${PHASES[@]}"; do
  run_phase "$phase"
done

set +e
phase_report | tee "$(log_path report)"
report_rc=${PIPESTATUS[0]}
set -e
if (( report_rc == 0 )); then
  record_status report ok
else
  record_status report failed
  OVERALL_STATUS=1
fi
exit "$OVERALL_STATUS"
