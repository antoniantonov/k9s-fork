#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of K9s
#
# Populates a minimal but complete set of workloads and NetworkPolicies to
# exercise the K9s NetworkPolicy reachability view (:netpolgraph / :npgraph /
# :npg, or Shift-R from Pod/Deployment/Job/Namespace views).
#
# The topology deliberately covers every result state and primitive kind the
# view can render:
#
#   Subjects      Pod, Deployment, Job (active + completed), Namespace
#   Primitives    CIDR, Pod, Namespace, Deployment, Job
#   States        Allowed, Disallowed, Partial (mixed pod pairs), Unknown
#                 (ambiguous named port + zero-replica workload)
#   Rules         podSelector-only, namespaceSelector-only, both (intersection),
#                 ipBlock with except, empty from/to (allow-all), empty ports,
#                 named ports, numeric ports, endPort ranges, default deny,
#                 and unrestricted (no isolating policy)
#   Owners        Deployment/ReplicaSet, Job, StatefulSet, DaemonSet, bare pod
#
# Usage:
#   ./scripts/netpol-demo-workloads.sh [options]
#
# Options:
#   --kubeconfig PATH    kubeconfig to use (default: exported kind kubeconfig)
#   --context NAME       kube context to use
#   --prefix NAME        namespace prefix (default: netpol-demo)
#   --cluster NAME       kind cluster to create or reuse (default: k9s-netpol)
#   --kind-cluster NAME  alias for --cluster
#   --node-image REF     kind node image to use (default: kindest/node:v1.34.0)
#   --image REF          container image to use (default: busybox:1.36)
#   --no-cluster         skip kind bootstrap and use the current kubeconfig/context
#   --delete-cluster     delete the kind cluster and exported kubeconfigs, then exit
#   --check, --status    verify the demo topology is already applied and ready; no mutations
#   --no-wait            do not wait for pods to become ready
#   --timeout DURATION   readiness wait timeout (default: 180s)
#   --delete             delete everything this script creates, then exit
#   -h, --help           show this help
# END_USAGE

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PREFIX="netpol-demo"
IMAGE="busybox:1.36"
KUBECONFIG_ARG=""
CONTEXT_ARG=""
CLUSTER="k9s-netpol"
NODE_IMAGE="kindest/node:v1.34.0"
NO_CLUSTER=0
WAIT=1
TIMEOUT="180s"
DELETE=0
DELETE_CLUSTER=0
CHECK=0

usage() {
  awk '
    NR > 1 {
      if ($0 == "# END_USAGE") exit
      sub(/^# ?/, "")
      print
    }
  ' "$0"
}

build_kubectl() {
  KUBECTL=(kubectl)
  [[ -n "$KUBECONFIG_ARG" ]] && KUBECTL+=(--kubeconfig "$KUBECONFIG_ARG")
  [[ -n "$CONTEXT_ARG" ]] && KUBECTL+=(--context "$CONTEXT_ARG")
  return 0
}

require_command() {
  command -v "$1" >/dev/null || { echo "$1 not found in PATH" >&2; exit 1; }
}

duration_to_seconds() {
  local value="$1" number unit
  if [[ "$value" =~ ^([0-9]+)(s|m|h)?$ ]]; then
    number="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2]:-s}"
    case "$unit" in
      s) echo "$number" ;;
      m) echo $((number * 60)) ;;
      h) echo $((number * 3600)) ;;
    esac
    return 0
  fi
  echo "180"
}

wait_for_api_server() {
  echo "==> waiting for Kubernetes API server (timeout: $TIMEOUT)"
  local deadline now
  deadline=$((SECONDS + $(duration_to_seconds "$TIMEOUT")))
  while (( SECONDS < deadline )); do
    if "${KUBECTL[@]}" version -o json >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "timed out waiting for the Kubernetes API server" >&2
  exit 1
}

export_kind_kubeconfigs() {
  mkdir -p "$REPO_ROOT/.kube"
  kind get kubeconfig --name "$CLUSTER" >"$HOST_KUBECONFIG"
  kind get kubeconfig --name "$CLUSTER" --internal >"$INTERNAL_KUBECONFIG"
  chmod 600 "$HOST_KUBECONFIG" "$INTERNAL_KUBECONFIG"
  echo "==> exported kubeconfigs:"
  echo "    $HOST_KUBECONFIG"
  echo "    $INTERNAL_KUBECONFIG"
}


check_resource() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf '  [ok]   %s\n' "$description"
    return 0
  fi
  printf '  [miss] %s\n' "$description"
  return 1
}

check_ready_pod_for_selector() {
  local description="$1" namespace="$2" selector="$3" ready
  ready=$("${KUBECTL[@]}" get pods -n "$namespace" -l "$selector" \
    -o jsonpath='{range .items[?(@.status.phase=="Running")]}{range .status.containerStatuses[*]}{.ready}{"\n"}{end}{end}' 2>/dev/null || true)
  if printf '%s\n' "$ready" | grep -qx true; then
    printf '  [ok]   %s\n' "$description"
    return 0
  fi
  printf '  [miss] %s\n' "$description"
  return 1
}

check_topology() {
  local failures=0 ns
  echo "==> checking NetworkPolicy demo topology (prefix: $PREFIX)"

  for ns in "${ALL_NS[@]}"; do
    check_resource "namespace $ns" "${KUBECTL[@]}" get namespace "$ns" || failures=$((failures + 1))
  done

  check_resource "app deployments" "${KUBECTL[@]}" get deployment -n "$NS_APP" api db ambiguous-ports scaled-to-zero || failures=$((failures + 1))
  check_resource "app jobs" "${KUBECTL[@]}" get job -n "$NS_APP" db-migration report-generator || failures=$((failures + 1))
  check_resource "app statefulset cache" "${KUBECTL[@]}" get statefulset -n "$NS_APP" cache || failures=$((failures + 1))
  check_resource "app daemonset log-collector" "${KUBECTL[@]}" get daemonset -n "$NS_APP" log-collector || failures=$((failures + 1))
  check_resource "app bare pod standalone-debug" "${KUBECTL[@]}" get pod -n "$NS_APP" standalone-debug || failures=$((failures + 1))
  check_resource "web deployments" "${KUBECTL[@]}" get deployment -n "$NS_WEB" frontend legacy || failures=$((failures + 1))
  check_resource "monitoring deployment" "${KUBECTL[@]}" get deployment -n "$NS_MON" prometheus || failures=$((failures + 1))
  check_resource "untrusted deployment" "${KUBECTL[@]}" get deployment -n "$NS_UNTRUSTED" client || failures=$((failures + 1))
  check_resource "open deployment" "${KUBECTL[@]}" get deployment -n "$NS_OPEN" open-app || failures=$((failures + 1))

  check_resource "app network policies" "${KUBECTL[@]}" get networkpolicy -n "$NS_APP" default-deny-all allow-frontend-ingress allow-monitoring-ingress allow-cidr-ingress allow-dns-egress allow-api-egress-db allow-db-ingress-api allow-api-egress-external allow-api-egress-ambiguous allow-ambiguous-ingress-api allow-cache-ingress-all || failures=$((failures + 1))
  check_resource "web network policies" "${KUBECTL[@]}" get networkpolicy -n "$NS_WEB" web-default-deny-egress frontend-egress-to-api || failures=$((failures + 1))
  check_resource "untrusted network policy" "${KUBECTL[@]}" get networkpolicy -n "$NS_UNTRUSTED" deny-all-egress || failures=$((failures + 1))

  for ns in "$NS_APP" "$NS_WEB" "$NS_MON" "$NS_UNTRUSTED" "$NS_OPEN"; do
    check_resource "deployments ready in $ns" "${KUBECTL[@]}" wait --for=condition=Available deployment --all -n "$ns" --timeout=1s || failures=$((failures + 1))
  done
  check_resource "statefulset cache rolled out" "${KUBECTL[@]}" rollout status statefulset/cache -n "$NS_APP" --timeout=1s || failures=$((failures + 1))
  check_resource "daemonset log-collector rolled out" "${KUBECTL[@]}" rollout status daemonset/log-collector -n "$NS_APP" --timeout=1s || failures=$((failures + 1))
  check_ready_pod_for_selector "report-generator has a running ready pod" "$NS_APP" "job-name=report-generator" || failures=$((failures + 1))
  check_resource "standalone-debug pod ready" "${KUBECTL[@]}" wait --for=condition=Ready pod/standalone-debug -n "$NS_APP" --timeout=1s || failures=$((failures + 1))
  check_resource "db-migration completed" "${KUBECTL[@]}" wait --for=condition=Complete job/db-migration -n "$NS_APP" --timeout=1s || failures=$((failures + 1))

  if (( failures == 0 )); then
    echo "==> demo topology is applied and ready"
    return 0
  fi
  echo "==> demo topology is incomplete or not ready ($failures check(s) failed)" >&2
  return 1
}

bootstrap_kind_cluster() {
  local control_plane="${CLUSTER}-control-plane"
  local cluster_exists=0
  kind get clusters 2>/dev/null | grep -Fx "$CLUSTER" >/dev/null && cluster_exists=1

  if [[ "$cluster_exists" -eq 1 ]] && [[ "$(docker inspect -f '{{.State.Running}}' "$control_plane" 2>/dev/null || true)" == "true" ]]; then
    echo "==> reusing running kind cluster $CLUSTER"
  elif docker inspect "$control_plane" >/dev/null 2>&1; then
    echo "==> starting stopped kind control-plane container $control_plane"
    docker start "$control_plane" >/dev/null
  else
    if [[ "$cluster_exists" -eq 1 ]]; then
      echo "==> removing stale kind cluster metadata for $CLUSTER"
      kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
    fi
    echo "==> creating kind cluster $CLUSTER with node image $NODE_IMAGE"
    kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE"
  fi

  export_kind_kubeconfigs
  if [[ -z "$KUBECONFIG_ARG" ]]; then
    KUBECONFIG_ARG="$HOST_KUBECONFIG"
  fi
  build_kubectl
  wait_for_api_server
  echo "==> waiting for kind node to be Ready (timeout: $TIMEOUT)"
  "${KUBECTL[@]}" wait --for=condition=Ready nodes --all --timeout="$TIMEOUT"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KUBECONFIG_ARG="$2"; shift 2 ;;
    --context) CONTEXT_ARG="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --cluster|--kind-cluster) CLUSTER="$2"; shift 2 ;;
    --node-image) NODE_IMAGE="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --no-cluster) NO_CLUSTER=1; shift ;;
    --delete-cluster) DELETE_CLUSTER=1; shift ;;
    --no-wait) WAIT=0; shift ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --delete) DELETE=1; shift ;;
    --check|--status) CHECK=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

HOST_KUBECONFIG="$REPO_ROOT/.kube/${CLUSTER}.kubeconfig"
INTERNAL_KUBECONFIG="$REPO_ROOT/.kube/${CLUSTER}.internal.kubeconfig"

NS_APP="${PREFIX}-app"
NS_WEB="${PREFIX}-web"
NS_MON="${PREFIX}-monitoring"
NS_UNTRUSTED="${PREFIX}-untrusted"
NS_OPEN="${PREFIX}-open"
ALL_NS=("$NS_APP" "$NS_WEB" "$NS_MON" "$NS_UNTRUSTED" "$NS_OPEN")

if [[ "$DELETE_CLUSTER" -eq 1 ]]; then
  require_command kind
  echo "==> deleting kind cluster $CLUSTER"
  kind delete cluster --name "$CLUSTER"
  rm -f "$HOST_KUBECONFIG" "$INTERNAL_KUBECONFIG"
  echo "==> removed exported kubeconfigs:"
  echo "    $HOST_KUBECONFIG"
  echo "    $INTERNAL_KUBECONFIG"
  exit 0
fi

require_command kubectl

if [[ "$CHECK" -eq 1 ]]; then
  if [[ "$NO_CLUSTER" -eq 0 && -z "$KUBECONFIG_ARG" ]]; then
    if [[ -f "$HOST_KUBECONFIG" ]]; then
      KUBECONFIG_ARG="$HOST_KUBECONFIG"
    elif [[ -z "$CONTEXT_ARG" ]]; then
      CONTEXT_ARG="kind-${CLUSTER}"
    fi
  fi
  build_kubectl
  "${KUBECTL[@]}" version -o json >/dev/null 2>&1 || {
    echo "cannot reach the cluster; check --kubeconfig/--context or run without --check to bootstrap" >&2
    exit 1
  }
  check_topology
  exit $?
fi

if [[ "$NO_CLUSTER" -eq 0 ]]; then
  require_command docker
  require_command kind
  bootstrap_kind_cluster
else
  build_kubectl
  "${KUBECTL[@]}" version -o json >/dev/null 2>&1 || {
    echo "cannot reach the cluster; check --kubeconfig/--context" >&2
    exit 1
  }
fi

if [[ "$DELETE" -eq 1 ]]; then
  echo "==> deleting namespaces: ${ALL_NS[*]}"
  "${KUBECTL[@]}" delete namespace "${ALL_NS[@]}" --ignore-not-found --wait=true
  echo "==> done"
  exit 0
fi

if [[ "$NO_CLUSTER" -eq 0 ]]; then
  echo "==> preloading $IMAGE into kind cluster $CLUSTER"
  docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"
  kind load docker-image "$IMAGE" --name "$CLUSTER"
fi

# Long-running command: busybox has no `sleep infinity`, so loop instead.
IDLE_CMD='while true; do sleep 3600; done'

echo "==> applying namespaces, workloads and network policies (prefix: $PREFIX)"

"${KUBECTL[@]}" apply -f - <<YAML
################################################################################
# Namespaces. Labels drive namespaceSelector peers in the policies below.
################################################################################
apiVersion: v1
kind: Namespace
metadata:
  name: ${NS_APP}
  labels: {netpol-demo: "true", team: app, tier: backend}
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${NS_WEB}
  labels: {netpol-demo: "true", team: web, tier: frontend}
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${NS_MON}
  labels: {netpol-demo: "true", team: observability}
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${NS_UNTRUSTED}
  labels: {netpol-demo: "true", team: untrusted}
---
# No NetworkPolicy targets this namespace: it stays unrestricted in both
# directions and produces the synthetic "Unrestricted (no isolating policy)"
# rule plus the "all cluster pods" node.
apiVersion: v1
kind: Namespace
metadata:
  name: ${NS_OPEN}
  labels: {netpol-demo: "true", team: open}
---
################################################################################
# ${NS_APP}: the main subject namespace.
################################################################################
# Primary subject. 3 replicas so aggregates report real pod-pair counts.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: ${NS_APP}
  labels: {app: api}
spec:
  replicas: 3
  selector:
    matchLabels: {app: api}
  template:
    metadata:
      labels: {app: api, tier: backend}
    spec:
      containers:
        - name: api
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          ports:
            - {name: http, containerPort: 8080, protocol: TCP}
            - {name: metrics, containerPort: 9090, protocol: TCP}
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
# Egress target with a resolvable named port (postgres -> 5432).
apiVersion: apps/v1
kind: Deployment
metadata:
  name: db
  namespace: ${NS_APP}
  labels: {app: db}
spec:
  replicas: 1
  selector:
    matchLabels: {app: db}
  template:
    metadata:
      labels: {app: db, tier: data}
    spec:
      containers:
        - name: db
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          ports:
            - {name: postgres, containerPort: 5432, protocol: TCP}
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
# Two containers expose the same port name on different numbers, so the named
# port "data" cannot be resolved -> Unknown access state.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ambiguous-ports
  namespace: ${NS_APP}
  labels: {app: ambiguous-ports}
spec:
  replicas: 1
  selector:
    matchLabels: {app: ambiguous-ports}
  template:
    metadata:
      labels: {app: ambiguous-ports}
    spec:
      containers:
        - name: first
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          ports:
            - {name: data, containerPort: 8081, protocol: TCP}
          resources:
            requests: {cpu: 5m, memory: 8Mi}
        - name: second
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          ports:
            - {name: data, containerPort: 8082, protocol: TCP}
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
# Zero replicas -> workload aggregate must render white with Unknown.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scaled-to-zero
  namespace: ${NS_APP}
  labels: {app: scaled-to-zero}
spec:
  replicas: 0
  selector:
    matchLabels: {app: scaled-to-zero}
  template:
    metadata:
      labels: {app: scaled-to-zero}
    spec:
      containers:
        - name: idle
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
# Completed Job: a valid subject whose pods are no longer running.
apiVersion: batch/v1
kind: Job
metadata:
  name: db-migration
  namespace: ${NS_APP}
  labels: {app: db-migration}
spec:
  backoffLimit: 2
  template:
    metadata:
      labels: {app: db-migration}
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "echo migrating; sleep 3; echo done"]
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
# Active Job: Job primitive and Job subject with live pods.
apiVersion: batch/v1
kind: Job
metadata:
  name: report-generator
  namespace: ${NS_APP}
  labels: {app: report-generator}
spec:
  backoffLimit: 2
  template:
    metadata:
      labels: {app: report-generator}
    spec:
      restartPolicy: Never
      containers:
        - name: report
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
# StatefulSet pods: unsupported owner, so they appear as Pod primitives only.
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: cache
  namespace: ${NS_APP}
  labels: {app: cache}
spec:
  serviceName: cache
  replicas: 2
  selector:
    matchLabels: {app: cache}
  template:
    metadata:
      labels: {app: cache}
    spec:
      containers:
        - name: cache
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          ports:
            - {name: redis, containerPort: 6379, protocol: TCP}
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
# DaemonSet pods: another unsupported owner rendered as Pod primitives.
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: log-collector
  namespace: ${NS_APP}
  labels: {app: log-collector}
spec:
  selector:
    matchLabels: {app: log-collector}
  template:
    metadata:
      labels: {app: log-collector}
    spec:
      containers:
        - name: collector
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
# Bare pod with no owner reference.
apiVersion: v1
kind: Pod
metadata:
  name: standalone-debug
  namespace: ${NS_APP}
  labels: {app: standalone-debug}
spec:
  containers:
    - name: debug
      image: ${IMAGE}
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "${IDLE_CMD}"]
      resources:
        requests: {cpu: 5m, memory: 8Mi}
---
################################################################################
# ${NS_WEB}: mixed results so namespace aggregates land on [PARTIAL x/y].
################################################################################
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: ${NS_WEB}
  labels: {app: frontend}
spec:
  replicas: 2
  selector:
    matchLabels: {app: frontend}
  template:
    metadata:
      labels: {app: frontend, role: web}
    spec:
      containers:
        - name: frontend
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          ports:
            - {name: http, containerPort: 80, protocol: TCP}
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
# Egress-isolated with no allow rule -> always disallowed.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: legacy
  namespace: ${NS_WEB}
  labels: {app: legacy}
spec:
  replicas: 1
  selector:
    matchLabels: {app: legacy}
  template:
    metadata:
      labels: {app: legacy, role: web}
    spec:
      containers:
        - name: legacy
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
################################################################################
# ${NS_MON}: no policies, so egress is unrestricted here.
################################################################################
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: ${NS_MON}
  labels: {app: prometheus}
spec:
  replicas: 1
  selector:
    matchLabels: {app: prometheus}
  template:
    metadata:
      labels: {app: prometheus, role: monitoring}
    spec:
      containers:
        - name: prometheus
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          ports:
            - {name: scrape, containerPort: 9090, protocol: TCP}
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
################################################################################
# ${NS_UNTRUSTED}: fully egress-denied.
################################################################################
apiVersion: apps/v1
kind: Deployment
metadata:
  name: client
  namespace: ${NS_UNTRUSTED}
  labels: {app: client}
spec:
  replicas: 1
  selector:
    matchLabels: {app: client}
  template:
    metadata:
      labels: {app: client}
    spec:
      containers:
        - name: client
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
################################################################################
# ${NS_OPEN}: no policies at all.
################################################################################
apiVersion: apps/v1
kind: Deployment
metadata:
  name: open-app
  namespace: ${NS_OPEN}
  labels: {app: open-app}
spec:
  replicas: 1
  selector:
    matchLabels: {app: open-app}
  template:
    metadata:
      labels: {app: open-app}
    spec:
      containers:
        - name: open
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "${IDLE_CMD}"]
          resources:
            requests: {cpu: 5m, memory: 8Mi}
---
################################################################################
# NetworkPolicies for ${NS_APP}.
################################################################################
# Isolates every pod in the namespace for both directions. Disallowed results
# are explained as isolation + no matching allow rule.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: ${NS_APP}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
# Single peer with BOTH selectors: intersection of namespace and pod selectors.
# Named port "http" resolves to 8080 on the api pods.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-ingress
  namespace: ${NS_APP}
spec:
  podSelector:
    matchLabels: {app: api}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: {team: web}
          podSelector:
            matchLabels: {app: frontend}
      ports:
        - {protocol: TCP, port: http}
---
# namespaceSelector alone: every pod in matching namespaces.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring-ingress
  namespace: ${NS_APP}
spec:
  podSelector:
    matchLabels: {app: api}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: {team: observability}
      ports:
        - {protocol: TCP, port: 9090}
---
# ipBlock ingress peer with except -> CIDR primitives in the ingress panel.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-cidr-ingress
  namespace: ${NS_APP}
spec:
  podSelector:
    matchLabels: {app: api}
  policyTypes: [Ingress]
  ingress:
    - from:
        - ipBlock:
            cidr: 192.168.0.0/16
            except: [192.168.5.0/24]
      ports:
        - {protocol: TCP, port: 8080}
---
# Namespace-wide DNS egress. Selects kube-system by its metadata.name label.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: ${NS_APP}
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels: {kubernetes.io/metadata.name: kube-system}
          podSelector:
            matchLabels: {k8s-app: kube-dns}
      ports:
        - {protocol: UDP, port: 53}
        - {protocol: TCP, port: 53}
---
# podSelector-only egress peer (same namespace) with a named port and an
# endPort range.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-egress-db
  namespace: ${NS_APP}
spec:
  podSelector:
    matchLabels: {app: api}
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels: {app: db}
      ports:
        - {protocol: TCP, port: postgres}
        - {protocol: TCP, port: 8000, endPort: 8100}
---
# The opposite side of the api -> db edge; without it the edge is disallowed.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-db-ingress-api
  namespace: ${NS_APP}
spec:
  podSelector:
    matchLabels: {app: db}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels: {app: api}
      ports:
        - {protocol: TCP, port: postgres}
---
# Two ipBlock peers (union), one of which is an unbounded range.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-egress-external
  namespace: ${NS_APP}
spec:
  podSelector:
    matchLabels: {app: api}
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
            except: [10.96.0.0/12, 10.244.0.0/16]
        - ipBlock:
            cidr: 0.0.0.0/0
            except: [169.254.0.0/16]
      ports:
        - {protocol: TCP, port: 443}
---
# Ambiguous named port on both sides -> Unknown, not optimistically allowed.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-egress-ambiguous
  namespace: ${NS_APP}
spec:
  podSelector:
    matchLabels: {app: api}
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels: {app: ambiguous-ports}
      ports:
        - {protocol: TCP, port: data}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ambiguous-ingress-api
  namespace: ${NS_APP}
spec:
  podSelector:
    matchLabels: {app: ambiguous-ports}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels: {app: api}
      ports:
        - {protocol: TCP, port: data}
---
# Empty rule: no "from" and no "ports" -> all sources on all ports.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-cache-ingress-all
  namespace: ${NS_APP}
spec:
  podSelector:
    matchLabels: {app: cache}
  policyTypes: [Ingress]
  ingress:
    - {}
---
################################################################################
# NetworkPolicies for ${NS_WEB}.
################################################################################
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-default-deny-egress
  namespace: ${NS_WEB}
spec:
  podSelector: {}
  policyTypes: [Egress]
---
# Only "frontend" may egress to the api; "legacy" stays denied, which makes the
# ${NS_WEB} namespace aggregate partial.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-egress-to-api
  namespace: ${NS_WEB}
spec:
  podSelector:
    matchLabels: {app: frontend}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels: {team: app}
          podSelector:
            matchLabels: {app: api}
      ports:
        - {protocol: TCP, port: 8080}
---
################################################################################
# NetworkPolicies for ${NS_UNTRUSTED}: isolated with no allow rule at all.
################################################################################
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
  namespace: ${NS_UNTRUSTED}
spec:
  podSelector: {}
  policyTypes: [Egress]
YAML

if [[ "$WAIT" -eq 1 ]]; then
  echo "==> waiting for workload pods to be ready (timeout: $TIMEOUT)"
  for ns in "$NS_APP" "$NS_WEB" "$NS_MON" "$NS_UNTRUSTED" "$NS_OPEN"; do
    "${KUBECTL[@]}" wait --for=condition=Ready pod --all -n "$ns" \
      --timeout="$TIMEOUT" 2>/dev/null || true
  done
  echo "==> waiting for job db-migration to complete"
  "${KUBECTL[@]}" wait --for=condition=Complete job/db-migration -n "$NS_APP" \
    --timeout="$TIMEOUT" || true
fi

echo
echo "==> workload summary"
for ns in "${ALL_NS[@]}"; do
  pods=$("${KUBECTL[@]}" get pods -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')
  deps=$("${KUBECTL[@]}" get deployments -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')
  jobs=$("${KUBECTL[@]}" get jobs -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')
  nps=$("${KUBECTL[@]}" get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')
  printf '    %-28s pods=%-3s deployments=%-3s jobs=%-3s networkpolicies=%s\n' \
    "$ns" "$pods" "$deps" "$jobs" "$nps"
done

echo
echo "==> exported kubeconfigs"
cat <<EOF
    host:      $HOST_KUBECONFIG
    internal:  $INTERNAL_KUBECONFIG
EOF

echo
echo "==> launch k9s with the demo graph"
cat <<EOF
    cd $REPO_ROOT && ./execs/k9s --context kind-${CLUSTER} -c "npg deployment api ${NS_APP}"
    docker run --rm -it --network kind -v "$INTERNAL_KUBECONFIG:/root/.kube/config" k9s-docker:v0.0.1 -c "npg deployment api ${NS_APP}"
EOF

echo
echo "==> try these in k9s"
cat <<EOF
    :npg deployment api ${NS_APP}        # green frontend/prometheus, partial ${NS_WEB},
                                          # unknown ambiguous-ports and scaled-to-zero
    :npg namespace ${NS_APP}             # namespace-wide aggregate
    :npg job report-generator ${NS_APP}  # active job subject
    :npg job db-migration ${NS_APP}      # completed job subject
    :npg pod standalone-debug ${NS_APP}  # isolated pod, default deny only
    :npg deployment open-app ${NS_OPEN}  # unrestricted, no isolating policy
    :pod / :dp / :job / :ns then Shift-R # contextual action
EOF
echo
echo "==> done. Remove everything with: $0 --delete --prefix ${PREFIX}"
