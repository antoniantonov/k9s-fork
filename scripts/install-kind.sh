#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of K9s
#
# Ensures the local kind (Kubernetes IN Docker) cluster used for K9s
# development is up. Installs the kind CLI on demand, creates or reuses the
# cluster, exports host and internal kubeconfigs, and waits for the node to
# be Ready. Idempotent: safe to run repeatedly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CLUSTER="${CLUSTER:-k9s-netpol}"
NODE_IMAGE="${NODE_IMAGE:-kindest/node:v1.34.0}"
KIND_VERSION="${KIND_VERSION:-v0.32.0}"
CHECK=0
DELETE=0
KIND_BIN=""

usage() {
  cat <<EOF
Usage: $0 [options]

Ensures the kind cluster used for K9s development is up, installing the kind
CLI on demand and exporting kubeconfigs under .kube/.

Options:
  --cluster NAME       kind cluster name (default: k9s-netpol).
  --node-image REF     kind node image to use (default: kindest/node:v1.34.0).
  --kind-version VER   kind CLI version to install if missing (default: v0.32.0).
  --check, --status    report the current state only; no mutations.
  --delete             delete the kind cluster and exported kubeconfigs, then exit.
  -h, --help           show this help.

Environment:
  CLUSTER              same as --cluster.
  NODE_IMAGE           same as --node-image.
  KIND_VERSION         same as --kind-version.
EOF
}

die() {
  echo "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null || die "$1 not found in PATH"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --cluster)
        [[ $# -ge 2 ]] || die "--cluster requires a name"
        CLUSTER="$2"
        shift 2
        ;;
      --node-image)
        [[ $# -ge 2 ]] || die "--node-image requires a reference"
        NODE_IMAGE="$2"
        shift 2
        ;;
      --kind-version)
        [[ $# -ge 2 ]] || die "--kind-version requires a version"
        KIND_VERSION="$2"
        shift 2
        ;;
      --check|--status)
        CHECK=1
        shift
        ;;
      --delete)
        DELETE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
  done
}

require_docker_daemon() {
  docker info >/dev/null 2>&1 || {
    die "cannot reach the Docker daemon; start Docker and verify 'docker info' succeeds"
  }
}

# Resolves KIND_BIN to an already-installed kind, without installing anything.
resolve_kind_bin_readonly() {
  if command -v kind >/dev/null 2>&1; then
    KIND_BIN="$(command -v kind)"
    return 0
  fi
  return 1
}

# Ensures kind is available, installing it via 'go install' if missing.
ensure_kind_installed() {
  if command -v kind >/dev/null 2>&1; then
    KIND_BIN="$(command -v kind)"
    return 0
  fi

  echo "==> kind not found in PATH; installing sigs.k8s.io/kind@${KIND_VERSION}"
  require_command go

  local gobin bindir
  gobin="$(go env GOBIN)"
  if [[ -n "$gobin" ]]; then
    bindir="$gobin"
  else
    bindir="$(go env GOPATH)/bin"
  fi

  GOBIN="$bindir" go install "sigs.k8s.io/kind@${KIND_VERSION}"
  echo "==> installed kind ${KIND_VERSION} to $bindir"

  KIND_BIN="$bindir/kind"
  [[ -x "$KIND_BIN" ]] || die "kind install did not produce an executable at $KIND_BIN"
}

# Mirrors bootstrap_kind_cluster() in netpol-demo-workloads.sh so both
# scripts converge on the same cluster state.
bootstrap_kind_cluster() {
  local control_plane="${CLUSTER}-control-plane"
  local cluster_exists=0
  "$KIND_BIN" get clusters 2>/dev/null | grep -Fx "$CLUSTER" >/dev/null && cluster_exists=1

  if [[ "$cluster_exists" -eq 1 ]] && [[ "$(docker inspect -f '{{.State.Running}}' "$control_plane" 2>/dev/null || true)" == "true" ]]; then
    echo "==> reusing running kind cluster $CLUSTER"
  elif docker inspect "$control_plane" >/dev/null 2>&1; then
    echo "==> starting stopped kind control-plane container $control_plane"
    docker start "$control_plane" >/dev/null
  else
    if [[ "$cluster_exists" -eq 1 ]]; then
      echo "==> removing stale kind cluster metadata for $CLUSTER"
      "$KIND_BIN" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
    fi
    echo "==> creating kind cluster $CLUSTER with node image $NODE_IMAGE"
    "$KIND_BIN" create cluster --name "$CLUSTER" --image "$NODE_IMAGE"
  fi
}

export_kind_kubeconfigs() {
  mkdir -p "$REPO_ROOT/.kube"

  local host_tmp="${HOST_KUBECONFIG}.tmp" internal_tmp="${INTERNAL_KUBECONFIG}.tmp"

  "$KIND_BIN" get kubeconfig --name "$CLUSTER" >"$host_tmp" || {
    rm -f "$host_tmp"
    die "cannot export host kubeconfig for kind cluster '$CLUSTER'"
  }
  chmod 600 "$host_tmp"
  mv "$host_tmp" "$HOST_KUBECONFIG"

  "$KIND_BIN" get kubeconfig --name "$CLUSTER" --internal >"$internal_tmp" || {
    rm -f "$internal_tmp"
    die "cannot export internal kubeconfig for kind cluster '$CLUSTER'"
  }
  chmod 600 "$internal_tmp"
  mv "$internal_tmp" "$INTERNAL_KUBECONFIG"

  echo "==> exported kubeconfigs:"
  echo "    $HOST_KUBECONFIG"
  echo "    $INTERNAL_KUBECONFIG"
}

wait_for_api_server() {
  echo "==> waiting for Kubernetes API server (timeout: 120s)"
  local deadline
  deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if kubectl --kubeconfig "$HOST_KUBECONFIG" version -o json >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  die "timed out waiting for the Kubernetes API server"
}

wait_for_node_ready() {
  echo "==> waiting for kind node to be Ready (timeout: 180s)"
  kubectl --kubeconfig "$HOST_KUBECONFIG" wait --for=condition=Ready nodes --all --timeout=180s
}

print_summary() {
  local network
  network="$(docker inspect "${CLUSTER}-control-plane" \
    --format '{{range $name,$settings := .NetworkSettings.Networks}}{{$name}} {{end}}' \
    2>/dev/null | awk '{print $1}')"

  echo
  echo "==> kind cluster ready:"
  echo "    cluster:              $CLUSTER"
  echo "    kube context:         kind-${CLUSTER}"
  echo "    node image:           $NODE_IMAGE"
  echo "    docker network:       ${network:-unknown}"
  echo "    host kubeconfig:      $HOST_KUBECONFIG"
  echo "    internal kubeconfig:  $INTERNAL_KUBECONFIG"
}

run_check() {
  local failures=0 control_plane="${CLUSTER}-control-plane"

  if docker info >/dev/null 2>&1; then
    echo "  [ok]   docker daemon reachable"
  else
    echo "  [miss] docker daemon reachable"
    failures=$((failures + 1))
  fi

  if resolve_kind_bin_readonly; then
    echo "  [ok]   kind binary present ($KIND_BIN)"
  else
    echo "  [miss] kind binary present"
    failures=$((failures + 1))
  fi

  if [[ -n "$KIND_BIN" ]] && "$KIND_BIN" get clusters 2>/dev/null | grep -Fx "$CLUSTER" >/dev/null; then
    echo "  [ok]   cluster registered ($CLUSTER)"
  else
    echo "  [miss] cluster registered ($CLUSTER)"
    failures=$((failures + 1))
  fi

  if [[ "$(docker inspect -f '{{.State.Running}}' "$control_plane" 2>/dev/null || true)" == "true" ]]; then
    echo "  [ok]   control-plane container running ($control_plane)"
  else
    echo "  [miss] control-plane container running ($control_plane)"
    failures=$((failures + 1))
  fi

  if (( failures == 0 )); then
    echo "==> kind cluster $CLUSTER is up"
    return 0
  fi
  echo "==> kind cluster $CLUSTER is not fully up ($failures check(s) failed)" >&2
  return 1
}

run_delete() {
  require_command docker
  ensure_kind_installed
  echo "==> deleting kind cluster $CLUSTER"
  "$KIND_BIN" delete cluster --name "$CLUSTER"
  rm -f "$HOST_KUBECONFIG" "$INTERNAL_KUBECONFIG"
  echo "==> removed exported kubeconfigs:"
  echo "    $HOST_KUBECONFIG"
  echo "    $INTERNAL_KUBECONFIG"
}

main() {
  parse_args "$@"

  HOST_KUBECONFIG="$REPO_ROOT/.kube/${CLUSTER}.kubeconfig"
  INTERNAL_KUBECONFIG="$REPO_ROOT/.kube/${CLUSTER}.internal.kubeconfig"

  require_command docker

  if (( CHECK == 1 )); then
    run_check
    return
  fi

  require_docker_daemon

  if (( DELETE == 1 )); then
    run_delete
    return
  fi

  require_command kubectl
  ensure_kind_installed
  bootstrap_kind_cluster
  export_kind_kubeconfigs
  wait_for_api_server
  wait_for_node_ready
  print_summary
}

main "$@"
