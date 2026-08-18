#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of K9s
#
# Thin delegate: the demo topology lives in scripts/netpol-demo-workloads.sh.
# Kept here so the skill's documented entry point keeps working.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
TARGET="$REPO_ROOT/scripts/netpol-demo-workloads.sh"

[[ -x "$TARGET" ]] || {
  echo "missing or non-executable script: $TARGET" >&2
  exit 1
}

exec "$TARGET" "$@"
