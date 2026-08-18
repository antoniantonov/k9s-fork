#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of K9s
#
# Builds a fresh local k9s Docker image, removes older k9s images and
# containers, prints the exact launch command, and runs it unless --build-only
# is supplied.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE_NAME="${IMAGE_NAME:-k9s}"
KIND_NETWORK="${KIND_NETWORK:-}"
KIND_CLUSTER="${KIND_CLUSTER:-k9s-netpol}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.34.0}"
NPG_DEPLOYMENT="${NPG_DEPLOYMENT:-api}"
NPG_NAMESPACE="${NPG_NAMESPACE:-netpol-demo-app}"
BUILD_ONLY=0
TEST_WORKLOADS=0
YES=0
KUBECONFIG_PATH=""
KUBE_CONTEXT=""
DOCKER_NETWORK=""
PREVIOUS_VERSION="none"
VERSION=""
IMAGE_REF=""
RUN_COMMAND=()

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --build-only         Build and print the run command without starting k9s.
  --kubeconfig PATH    Kubeconfig to mount inside the k9s container, for
                       targeting a cluster other than the local kind one.
                       Defaults to the internal kubeconfig of the local kind
                       cluster (\$KIND_CLUSTER).
  --test-workloads     Seed the NetworkPolicy demo topology into the local
                       kind cluster before starting k9s. Cannot be combined
                       with --kubeconfig.
  --yes, -y            Auto-answer yes to every prompt (e.g. installing the
                       local kind cluster); never blocks on input.
  -h, --help           Show this help.

Environment:
  IMAGE_NAME           Docker repository name (default: k9s).
  KIND_NETWORK         Override the detected kind Docker network.
  KIND_CLUSTER         Local kind cluster name (default: k9s-netpol).
  KIND_NODE_IMAGE      kind node image (default: kindest/node:v1.34.0).
  NPG_DEPLOYMENT       Deployment opened by default (default: api).
  NPG_NAMESPACE        Namespace opened by default (default: netpol-demo-app).

Unless --kubeconfig is given, this script verifies the local kind cluster is
running, installing/starting it via scripts/install-kind.sh when it is not
(prompting for confirmation unless --yes is set).
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
      --build-only)
        BUILD_ONLY=1
        shift
        ;;
      --kubeconfig)
        [[ $# -ge 2 ]] || die "--kubeconfig requires a path"
        KUBECONFIG_PATH="$2"
        shift 2
        ;;
      --test-workloads)
        TEST_WORKLOADS=1
        shift
        ;;
      --yes|-y)
        YES=1
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

validate_flags() {
  if (( TEST_WORKLOADS == 1 )) && [[ -n "$KUBECONFIG_PATH" ]]; then
    die "--test-workloads cannot be combined with --kubeconfig; the demo workloads must only be applied to the local '${KIND_CLUSTER}' kind cluster"
  fi
}

require_docker_daemon() {
  docker info >/dev/null 2>&1 || {
    die "cannot reach the Docker daemon; start Docker and verify 'docker info' succeeds"
  }
}

kind_preflight() {
  [[ -z "$KUBECONFIG_PATH" ]] || return 0

  if [[ "$(docker inspect -f '{{.State.Running}}' "${KIND_CLUSTER}-control-plane" 2>/dev/null || true)" == "true" ]]; then
    echo "==> kind cluster '${KIND_CLUSTER}' is running"
    return
  fi

  local answer
  if (( YES == 1 )); then
    echo "==> kind cluster '${KIND_CLUSTER}' is not running; --yes supplied, installing and starting it automatically"
    answer="y"
  elif [[ -t 0 ]]; then
    read -r -p "kind cluster '${KIND_CLUSTER}' is not running. Install and start it now? [y/N] " answer
  else
    die "kind cluster '${KIND_CLUSTER}' is not running; run 'scripts/install-kind.sh --cluster ${KIND_CLUSTER}' to install and start it, pass --yes to do so automatically, or pass --kubeconfig to target a different cluster"
  fi

  case "$answer" in
    y|Y|yes|YES|Yes)
      ;;
    *)
      die "kind cluster '${KIND_CLUSTER}' is not running; run 'scripts/install-kind.sh --cluster ${KIND_CLUSTER}' to install and start it, pass --yes to do so automatically, or pass --kubeconfig to target a different cluster"
      ;;
  esac

  [[ -x "$SCRIPT_DIR/install-kind.sh" ]] || die "scripts/install-kind.sh not found or not executable; cannot start kind cluster '${KIND_CLUSTER}'"
  echo "==> installing and starting kind cluster '${KIND_CLUSTER}'"
  "$SCRIPT_DIR/install-kind.sh" --cluster "$KIND_CLUSTER" --node-image "$KIND_NODE_IMAGE"
}

ensure_kind_on_path() {
  command -v kind >/dev/null 2>&1 && return 0

  command -v go >/dev/null 2>&1 || return 0

  local bindir
  bindir="$(go env GOBIN)"
  [[ -n "$bindir" ]] || bindir="$(go env GOPATH)/bin"

  if [[ -n "$bindir" && -x "$bindir/kind" ]]; then
    echo "==> kind not on PATH; adding $bindir (go-installed kind) to PATH"
    PATH="$bindir:$PATH"
    export PATH
  fi
}

seed_test_workloads() {
  (( TEST_WORKLOADS == 1 )) || return 0

  [[ -x "$SCRIPT_DIR/netpol-demo-workloads.sh" ]] || die "scripts/netpol-demo-workloads.sh not found or not executable"

  if ! "$SCRIPT_DIR/netpol-demo-workloads.sh" --cluster "$KIND_CLUSTER" --check; then
    echo "==> applying NetworkPolicy demo topology to kind cluster '${KIND_CLUSTER}'"
    "$SCRIPT_DIR/netpol-demo-workloads.sh" --cluster "$KIND_CLUSTER" || die "failed to apply NetworkPolicy demo topology to kind cluster '${KIND_CLUSTER}'"
  else
    echo "==> NetworkPolicy demo topology already applied to kind cluster '${KIND_CLUSTER}'"
  fi
}

resolve_next_version() {
  local tags major minor patch
  tags="$(docker image ls "$IMAGE_NAME" --format '{{.Tag}}' 2>/dev/null |
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' || true)"

  if [[ -z "$tags" ]]; then
    PREVIOUS_VERSION="none"
    VERSION="0.0.1"
    return
  fi

  PREVIOUS_VERSION="$(printf '%s\n' "$tags" |
    sort -t. -k1,1n -k2,2n -k3,3n |
    tail -n1)"
  IFS=. read -r major minor patch <<<"$PREVIOUS_VERSION"
  VERSION="${major}.${minor}.$((patch + 1))"
}

absolute_kubeconfig_path() {
  local directory filename
  [[ -f "$KUBECONFIG_PATH" ]] || die "kubeconfig does not exist: $KUBECONFIG_PATH"
  directory="$(cd "$(dirname "$KUBECONFIG_PATH")" && pwd)"
  filename="$(basename "$KUBECONFIG_PATH")"
  KUBECONFIG_PATH="${directory}/${filename}"
}

resolve_kubeconfig() {
  local internal_kubeconfig temporary

  if [[ -z "$KUBECONFIG_PATH" ]]; then
    internal_kubeconfig="$REPO_ROOT/.kube/${KIND_CLUSTER}.internal.kubeconfig"
    if command -v kind >/dev/null 2>&1; then
      mkdir -p "$REPO_ROOT/.kube"
      temporary="${internal_kubeconfig}.tmp"
      kind get kubeconfig --name "$KIND_CLUSTER" --internal >"$temporary" || {
        rm -f "$temporary"
        die "cannot export an internal kubeconfig for kind cluster '${KIND_CLUSTER}'"
      }
      mv "$temporary" "$internal_kubeconfig"
      chmod 600 "$internal_kubeconfig"
    fi
    [[ -f "$internal_kubeconfig" ]] ||
      die "no kubeconfig for kind cluster '${KIND_CLUSTER}'; run scripts/install-kind.sh or pass --kubeconfig"
    KUBECONFIG_PATH="$internal_kubeconfig"
  fi

  absolute_kubeconfig_path
  KUBE_CONTEXT="$(kubectl --kubeconfig "$KUBECONFIG_PATH" config current-context 2>/dev/null || true)"
}

resolve_docker_network() {
  local cluster
  DOCKER_NETWORK="$KIND_NETWORK"
  if [[ -z "$DOCKER_NETWORK" && "$KUBE_CONTEXT" == kind-* ]]; then
    cluster="${KUBE_CONTEXT#kind-}"
    DOCKER_NETWORK="$(docker inspect "${cluster}-control-plane" \
      --format '{{range $name,$settings := .NetworkSettings.Networks}}{{$name}} {{end}}' \
      2>/dev/null | awk '{print $1}')"
  fi
}

build_image() {
  IMAGE_REF="${IMAGE_NAME}:${VERSION}"
  echo "==> previous ${IMAGE_NAME} version: $PREVIOUS_VERSION"
  echo "==> building ${IMAGE_REF} from scratch"
  docker build --pull --no-cache -t "$IMAGE_REF" "$REPO_ROOT"
  echo "==> built image: $IMAGE_REF"
}

remove_containers_for_image() {
  local image_id="$1" container_id
  for container_id in $(docker container ls -aq --filter "ancestor=${image_id}"); do
    echo "==> stopping and removing k9s container: $container_id"
    docker container rm -f "$container_id" >/dev/null
  done
}

cleanup_previous_images() {
  local refs ref image_id
  refs="$(docker image ls "$IMAGE_NAME" --format '{{.Repository}}:{{.Tag}}' |
    grep -v -F -x "$IMAGE_REF" |
    grep -v ':<none>$' || true)"

  if [[ -z "$refs" ]]; then
    echo "==> no previous ${IMAGE_NAME} images to remove"
    return
  fi

  for ref in $refs; do
    image_id="$(docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true)"
    [[ -n "$image_id" ]] && remove_containers_for_image "$image_id"
  done
  for ref in $refs; do
    echo "==> removing previous image: $ref"
    docker image rm -f "$ref" >/dev/null
  done

  refs="$(docker image ls "$IMAGE_NAME" --format '{{.Repository}}:{{.Tag}}' |
    grep -v ':<none>$' || true)"
  [[ "$refs" == "$IMAGE_REF" ]] || die "expected only $IMAGE_REF to remain; found: ${refs:-none}"
}

build_run_command() {
  RUN_COMMAND=(docker run --rm -it)
  if [[ -n "$DOCKER_NETWORK" ]]; then
    RUN_COMMAND+=(--network "$DOCKER_NETWORK")
  fi
  RUN_COMMAND+=(
    -e TERM=xterm-256color
    -e KUBECONFIG=/root/.kube/config
    -v "${KUBECONFIG_PATH}:/root/.kube/config:ro"
    "$IMAGE_REF"
  )
  if [[ -n "$KUBE_CONTEXT" ]]; then
    RUN_COMMAND+=(--context "$KUBE_CONTEXT")
  fi
  RUN_COMMAND+=(-c "npg deployment ${NPG_DEPLOYMENT} ${NPG_NAMESPACE}")
}

print_run_command() {
  local argument
  echo
  echo "Run command:"
  printf '  '
  for argument in "${RUN_COMMAND[@]}"; do
    printf '%q ' "$argument"
  done
  printf '\n'
}

main() {
  parse_args "$@"
  validate_flags
  require_command docker
  require_command kubectl
  require_docker_daemon
  kind_preflight
  ensure_kind_on_path
  resolve_next_version
  resolve_kubeconfig
  resolve_docker_network
  seed_test_workloads
  build_image
  cleanup_previous_images
  build_run_command
  print_run_command

  if (( BUILD_ONLY == 1 )); then
    return
  fi

  echo
  echo "==> starting $IMAGE_REF"
  "${RUN_COMMAND[@]}"
}

main "$@"
