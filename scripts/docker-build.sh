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

main() {
  require_command docker
  require_docker_daemon

  resolve_next_version

  echo "==> previous ${IMAGE_NAME} version: $PREVIOUS_VERSION"
  echo "==> building ${IMAGE_NAME}:${VERSION}"
  docker build -t "${IMAGE_NAME}:${VERSION}" "$REPO_ROOT"

  cat <<EOF
==> built image: ${IMAGE_NAME}:${VERSION}

Sample run command:
docker run --rm -it \\
  -v "\$HOME/.kube/config:/root/.kube/config:ro" \\
  ${IMAGE_NAME}:${VERSION}

Note: local clusters (kind, minikube, Docker Desktop) usually also need
      --network host on Linux. To use a different kubeconfig, change the -v
      mount above or set KUBECONFIG inside the container.
EOF
}

main "$@"
