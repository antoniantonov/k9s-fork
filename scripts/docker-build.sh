#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of K9s
#
# Builds a local k9s Docker image with the next patch semantic-version tag and
# prints a ready-to-paste command for running the freshly built image.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE_NAME="${IMAGE_NAME:-k9s}"
KIND_CLUSTER="${KIND_CLUSTER:-}"
KIND_NETWORK="${KIND_NETWORK:-}"
NPG_DEPLOYMENT="${NPG_DEPLOYMENT:-api}"
NPG_NAMESPACE="${NPG_NAMESPACE:-netpol-demo-app}"
PREVIOUS_VERSION="none"
VERSION=""

require_command() {
  command -v "$1" >/dev/null || { echo "$1 not found in PATH" >&2; exit 1; }
}

require_docker_daemon() {
  docker info >/dev/null 2>&1 || {
    echo "cannot reach the Docker daemon; start Docker and verify 'docker info' succeeds" >&2
    exit 1
  }
}

resolve_next_version() {
  local tags
  tags="$(docker images --format '{{.Tag}}' "$IMAGE_NAME" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' || true)"

  if [[ -z "$tags" ]]; then
    PREVIOUS_VERSION="none"
    VERSION="0.0.1"
    return 0
  fi

  local major minor patch
  PREVIOUS_VERSION="$(printf '%s\n' "$tags" | sort -V | tail -n1)"
  IFS=. read -r major minor patch <<<"$PREVIOUS_VERSION"
  VERSION="${major}.${minor}.$((patch + 1))"
}

resolve_kind_target() {
  local current_context=""

  if [[ -z "$KIND_CLUSTER" ]] && command -v kubectl >/dev/null; then
    current_context="$(kubectl config current-context 2>/dev/null || true)"
    if [[ "$current_context" == kind-* ]]; then
      KIND_CLUSTER="${current_context#kind-}"
    fi
  fi
  KIND_CLUSTER="${KIND_CLUSTER:-k9s-netpol}"

  if [[ -z "$KIND_NETWORK" ]]; then
    KIND_NETWORK="$(docker inspect "${KIND_CLUSTER}-control-plane" \
      --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' \
      2>/dev/null | awk '{print $1}')"
  fi
  KIND_NETWORK="${KIND_NETWORK:-kind}"
}

main() {
  local internal_kubeconfig

  require_command docker
  require_docker_daemon

  resolve_next_version
  resolve_kind_target
  internal_kubeconfig="/tmp/${KIND_CLUSTER}.internal.kubeconfig"

  echo "==> previous ${IMAGE_NAME} version: $PREVIOUS_VERSION"
  echo "==> building ${IMAGE_NAME}:${VERSION}"
  docker build -t "${IMAGE_NAME}:${VERSION}" "$REPO_ROOT"

  cat <<EOF
==> built image: ${IMAGE_NAME}:${VERSION}

Run against kind cluster ${KIND_CLUSTER} and open the NetworkPolicy graph:
kind get kubeconfig --name "${KIND_CLUSTER}" --internal > "${internal_kubeconfig}" && \\
docker run --rm -it \\
  --network "${KIND_NETWORK}" \\
  -e TERM=xterm-256color \\
  -e KUBECONFIG=/root/.kube/config \\
  -v "${internal_kubeconfig}:/root/.kube/config:ro" \\
  ${IMAGE_NAME}:${VERSION} \\
  --context "kind-${KIND_CLUSTER}" \\
  -c "npg deployment ${NPG_DEPLOYMENT} ${NPG_NAMESPACE}"
EOF
}

main "$@"
