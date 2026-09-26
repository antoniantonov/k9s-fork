#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of K9s
#
# Optional conformance lane for the NetworkPolicy reachability graph. It runs
# real Cilium and Istio (sidecar mode) in a dedicated kind cluster, probes HTTP
# connections between a few pods, and compares the probe results with the
# graph's verdicts for the same live objects. The regular demo cluster and
# run-tests.sh are never touched.
#
# Probes address Services: Istio sidecars only use mTLS, and so only present a
# peer identity, for destinations they know as mesh endpoints. A bare pod IP is
# sent in plaintext, which the graph's identity note calls out.
#
# Usage:
#   ./scripts/netpol-conformance.sh [options]
#
# Options:
#   --cluster NAME         kind cluster to create or reuse (default: k9s-netpol-conformance)
#   --node-image REF       kind node image (default: kindest/node:v1.34.0)
#   --cilium-version VER   Cilium Helm chart version (default: 1.20.2)
#   --istio-version VER    Istio Helm chart version (default: 1.30.5)
#   --timeout DURATION     readiness wait timeout (default: 300s)
#   --results PATH         probe results file (default: runs/conformance-<timestamp>/probes.tsv)
#   --skip-install         reuse an installed cluster; only (re)apply workloads, probe and compare
#   --delete               delete the conformance cluster and exit
#   -h, --help             show this help
# END_USAGE

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CLUSTER="k9s-netpol-conformance"
NODE_IMAGE="kindest/node:v1.34.0"
CILIUM_VERSION="1.20.2"
ISTIO_VERSION="1.30.5"
TIMEOUT="300s"
RESULTS=""
SKIP_INSTALL=0
DELETE=0
AGNHOST_IMAGE="registry.k8s.io/e2e-test-images/agnhost:2.66.1"
CLIENT_IMAGE="busybox:1.36"
NS_MESH="conf-mesh"
NS_PLAIN="conf-plain"

usage() {
  awk '
    NR > 1 {
      if ($0 == "# END_USAGE") exit
      sub(/^# ?/, "")
      print
    }
  ' "$0"
}

require_command() {
  command -v "$1" >/dev/null || { echo "$1 not found in PATH" >&2; exit 1; }
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster) CLUSTER="$2"; shift 2 ;;
    --node-image) NODE_IMAGE="$2"; shift 2 ;;
    --cilium-version) CILIUM_VERSION="$2"; shift 2 ;;
    --istio-version) ISTIO_VERSION="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --results) RESULTS="$2"; shift 2 ;;
    --skip-install) SKIP_INSTALL=1; shift ;;
    --delete) DELETE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$CLUSTER" == "k9s-netpol" ]]; then
  echo "refusing to use the demo cluster k9s-netpol for the conformance lane" >&2
  exit 2
fi

KUBECONFIG_FILE="$REPO_ROOT/.github/skills/netpol-graph-testing/.kube/${CLUSTER}.kubeconfig"
KUBECTL=(kubectl --kubeconfig "$KUBECONFIG_FILE")

if (( DELETE == 1 )); then
  require_command kind
  kind delete cluster --name "$CLUSTER"
  rm -f "$KUBECONFIG_FILE"
  exit 0
fi

for command in docker kind kubectl helm go; do
  require_command "$command"
done

if [[ -z "$RESULTS" ]]; then
  RESULTS="$REPO_ROOT/.github/skills/netpol-graph-testing/runs/conformance-$(date +%Y%m%d-%H%M%S)-$$/probes.tsv"
fi
mkdir -p "$(dirname "$RESULTS")" "$(dirname "$KUBECONFIG_FILE")"

create_cluster() {
  if kind get clusters 2>/dev/null | grep -Fx "$CLUSTER" >/dev/null; then
    echo "==> reusing kind cluster $CLUSTER"
  else
    echo "==> creating kind cluster $CLUSTER without the default CNI"
    kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --config - <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
YAML
  fi
  kind get kubeconfig --name "$CLUSTER" >"$KUBECONFIG_FILE"
  chmod 600 "$KUBECONFIG_FILE"
}

install_cilium() {
  echo "==> installing Cilium $CILIUM_VERSION"
  helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
  helm repo update cilium >/dev/null
  helm upgrade --install cilium cilium/cilium --kubeconfig "$KUBECONFIG_FILE" \
    --namespace kube-system --version "$CILIUM_VERSION" \
    --set operator.replicas=1 --set ipam.mode=kubernetes \
    --set image.pullPolicy=IfNotPresent --wait --timeout "$TIMEOUT"
  "${KUBECTL[@]}" -n kube-system rollout status daemonset/cilium --timeout="$TIMEOUT"
  "${KUBECTL[@]}" wait --for=condition=Ready nodes --all --timeout="$TIMEOUT"
}

install_istio() {
  echo "==> installing Istio $ISTIO_VERSION (sidecar mode)"
  helm repo add istio https://istio-release.storage.googleapis.com/charts >/dev/null 2>&1 || true
  helm repo update istio >/dev/null
  helm upgrade --install istio-base istio/base --kubeconfig "$KUBECONFIG_FILE" \
    --namespace istio-system --create-namespace --version "$ISTIO_VERSION" --wait --timeout "$TIMEOUT"
  helm upgrade --install istiod istio/istiod --kubeconfig "$KUBECONFIG_FILE" \
    --namespace istio-system --version "$ISTIO_VERSION" --wait --timeout "$TIMEOUT"
  "${KUBECTL[@]}" -n istio-system rollout status deployment/istiod --timeout="$TIMEOUT"
}

apply_workloads() {
  echo "==> applying conformance workloads and policies"
  "${KUBECTL[@]}" apply -f - <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: ${NS_MESH}
  labels: {istio-injection: enabled}
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${NS_PLAIN}
---
apiVersion: v1
kind: Pod
metadata: {name: server, namespace: ${NS_MESH}, labels: {app: server}}
spec:
  containers:
    - {name: http-8080, image: ${AGNHOST_IMAGE}, args: [netexec, --http-port=8080, --udp-port=-1]}
    - {name: http-8081, image: ${AGNHOST_IMAGE}, args: [netexec, --http-port=8081, --udp-port=-1]}
---
apiVersion: v1
kind: Service
metadata: {name: server, namespace: ${NS_MESH}}
spec:
  selector: {app: server}
  ports:
    - {name: http-8080, port: 8080, targetPort: 8080}
    - {name: http-8081, port: 8081, targetPort: 8081}
---
apiVersion: v1
kind: Service
metadata: {name: plain-server, namespace: ${NS_PLAIN}}
spec:
  selector: {app: plain-server}
  ports: [{name: http-8080, port: 8080, targetPort: 8080}]
---
apiVersion: v1
kind: Pod
metadata: {name: client, namespace: ${NS_MESH}, labels: {app: client}}
spec:
  containers: [{name: client, image: ${CLIENT_IMAGE}, command: [sh, -c, "while true; do sleep 3600; done"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: denied-client, namespace: ${NS_MESH}, labels: {app: denied-client}}
spec:
  containers: [{name: client, image: ${CLIENT_IMAGE}, command: [sh, -c, "while true; do sleep 3600; done"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: plain-server, namespace: ${NS_PLAIN}, labels: {app: plain-server}}
spec:
  containers: [{name: http-8080, image: ${AGNHOST_IMAGE}, args: [netexec, --http-port=8080, --udp-port=-1]}]
---
apiVersion: v1
kind: Pod
metadata: {name: plain-client, namespace: ${NS_PLAIN}, labels: {app: plain-client}}
spec:
  containers: [{name: client, image: ${CLIENT_IMAGE}, command: [sh, -c, "while true; do sleep 3600; done"]}]
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: {name: server-ingress, namespace: ${NS_MESH}}
spec:
  endpointSelector: {matchLabels: {app: server}}
  ingress:
    - fromEndpoints:
        - matchLabels: {app: client}
        - matchLabels: {app: denied-client}
        - matchLabels: {app: plain-client, k8s:io.kubernetes.pod.namespace: ${NS_PLAIN}}
      toPorts: [{ports: [{port: "8080", protocol: TCP}, {port: "8081", protocol: TCP}]}]
  ingressDeny:
    - fromEndpoints: [{matchLabels: {app: denied-client}}]
      toPorts: [{ports: [{port: "8081", protocol: TCP}]}]
---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: server-authz, namespace: ${NS_MESH}}
spec:
  selector: {matchLabels: {app: server}}
  action: ALLOW
  rules:
    - from: [{source: {namespaces: [${NS_MESH}]}}]
      to: [{operation: {ports: ["8080"]}}]
---
# Not enforced: plain-server is outside the mesh.
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata: {name: plain-server-authz, namespace: ${NS_PLAIN}}
spec:
  selector: {matchLabels: {app: plain-server}}
  action: ALLOW
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: plain-client-egress, namespace: ${NS_PLAIN}}
spec:
  podSelector: {matchLabels: {app: plain-client}}
  policyTypes: [Egress]
  egress:
    - to: [{namespaceSelector: {}}]
      ports: [{protocol: TCP, port: 8080}]
YAML
  for namespace in "$NS_MESH" "$NS_PLAIN"; do
    "${KUBECTL[@]}" wait --for=condition=Ready pod --all -n "$namespace" --timeout="$TIMEOUT"
  done
}

# Each probe: source namespace, source pod, destination namespace, destination
# pod (also the name of the Service selecting it), TCP port.
PROBES=(
  "$NS_MESH client $NS_MESH server 8080"
  "$NS_MESH client $NS_MESH server 8081"
  "$NS_MESH denied-client $NS_MESH server 8080"
  "$NS_MESH denied-client $NS_MESH server 8081"
  "$NS_PLAIN plain-client $NS_MESH server 8080"
  "$NS_PLAIN plain-client $NS_MESH server 8081"
  "$NS_MESH client $NS_PLAIN plain-server 8080"
  "$NS_PLAIN plain-client $NS_PLAIN plain-server 8080"
)

probe_once() {
  local source_ns source destination_ns destination port ip
  read -r source_ns source destination_ns destination port <<<"$1"
  # The ClusterIP avoids DNS, which the plain client's egress policy blocks.
  ip="$("${KUBECTL[@]}" get service -n "$destination_ns" "$destination" -o jsonpath='{.spec.clusterIP}')"
  if "${KUBECTL[@]}" exec -n "$source_ns" "$source" -c client -- \
    wget -q -O /dev/null -T 3 "http://$ip:$port/hostname" >/dev/null 2>&1; then
    printf 'allowed'
  else
    printf 'denied'
  fi
}

# Policies take a few seconds to reach the dataplane, so probe until two
# consecutive rounds agree.
probe_all() {
  local previous="" current round probe
  for round in 1 2 3 4 5 6; do
    current=""
    for probe in "${PROBES[@]}"; do
      current+="$probe $(probe_once "$probe")"$'\n'
    done
    if [[ "$current" == "$previous" ]]; then
      printf '%s' "$current" >"$RESULTS"
      echo "==> probe results converged after $round rounds:"
      cat "$RESULTS"
      return 0
    fi
    previous="$current"
    sleep 5
  done
  printf '%s' "$current" >"$RESULTS"
  echo "probe results did not converge; latest round:" >&2
  cat "$RESULTS" >&2
  return 1
}

if (( SKIP_INSTALL == 0 )); then
  create_cluster
  install_cilium
  install_istio
else
  kind get kubeconfig --name "$CLUSTER" >"$KUBECONFIG_FILE"
fi
apply_workloads
probe_all
echo "==> comparing probe results with graph verdicts"
cd "$REPO_ROOT"
KUBECONFIG="$KUBECONFIG_FILE" NETPOL_CONFORMANCE_RESULTS="$RESULTS" \
  go test -tags conformance -count=1 -v ./internal/netpol/conformance/
echo "==> conformance lane passed; delete the cluster with: $0 --delete --cluster $CLUSTER"
