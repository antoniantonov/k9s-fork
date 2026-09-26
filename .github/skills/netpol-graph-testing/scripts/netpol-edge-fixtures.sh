#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of K9s

# Sourced by the demo entry point; all Kubernetes access uses its explicit
# KUBECTL array. Probe policies are opt-in because uncertainty is snapshot-wide.

edge_pods() {
  cat <<PODS
$NS_EDGE_SRC cnp-client cnp-client allowed
$NS_EDGE_SRC cnp-blocked cnp-client blocked
$NS_EDGE_SRC ccnp-client ccnp-client allowed
$NS_EDGE_SRC cnp-empty cnp-empty empty
$NS_EDGE_SRC ccnp-empty ccnp-empty empty
$NS_EDGE_SRC cidr-client cidr-client allowed
$NS_EDGE_SRC authz-client authz-client allowed
$NS_EDGE_SRC uncertain-client uncertain-client probe
$NS_EDGE_DST cnp-server cnp-server allowed
$NS_EDGE_DST cnp-denied cnp-server egress-denied
$NS_EDGE_DST cnp-mismatch cnp-mismatch mismatch
$NS_EDGE_DST ccnp-server ccnp-server allowed
$NS_EDGE_DST ccnp-denied ccnp-server egress-denied
$NS_EDGE_DST authz-server authz-server allowed
$NS_EDGE_DST authz-no-tcp authz-no-tcp restricted
$NS_EDGE_DST authz-closed authz-closed restricted
$NS_EDGE_DST authz-identity authz-identity probe
$NS_EDGE_OTHER control control control
PODS
}

check_resource_value() {
  local description="$1" expected="$2" actual
  shift 2
  if ! actual=$("$@" 2>/dev/null); then
    printf '  [miss] %s\n' "$description"
    return 1
  fi
  if [[ "$actual" != "$expected" ]]; then
    printf '  [stale] %s\n' "$description"
    return 1
  fi
  printf '  [ok]   %s\n' "$description"
}

edge_policy() {
  local resource="$1" kind="$2" version="$3" namespace="$4" name="$5" body="$6"
  local manifest expected actual owner probe_labels="" scope=()
  [[ -n "$namespace" ]] && scope=(-n "$namespace")
  if [[ -n "${PROBE:-}" ]]; then
    probe_labels=", \"netpol-demo-probe\": \"$PROBE\", \"netpol-demo-probe-id\": \"$PROBE_ID\""
  fi
  manifest=$(cat <<JSON
{
  "apiVersion": "$version", "kind": "$kind",
  "metadata": {
    "name": "$name", "namespace": "$namespace",
    "labels": {"netpol-demo-prefix": "$PREFIX", "netpol-demo-edge": "true"$probe_labels}
  },
  $body
}
JSON
)
  case "$EDGE_MODE" in
    check)
      expected=$(printf '%s\n' "$manifest" | "${KUBECTL[@]}" create \
        --dry-run=client --validate=false -f - -o jsonpath='{.spec}{"|"}{.specs}') || return 1
      check_resource_value "$kind $namespace/$name spec and specs" "$expected" \
        "${KUBECTL[@]}" get "$resource" "$name" ${scope[@]+"${scope[@]}"} \
        -o jsonpath='{.spec}{"|"}{.specs}' || return 1
      check_resource_value "$kind $namespace/$name ownership" "$PREFIX|true|${PROBE:-}|${PROBE_ID:-}" \
        "${KUBECTL[@]}" get "$resource" "$name" ${scope[@]+"${scope[@]}"} \
        -o jsonpath='{.metadata.labels.netpol-demo-prefix}{"|"}{.metadata.labels.netpol-demo-edge}{"|"}{.metadata.labels.netpol-demo-probe}{"|"}{.metadata.labels.netpol-demo-probe-id}'
      ;;
    apply|delete)
      owner=$("${KUBECTL[@]}" get "$resource" "$name" ${scope[@]+"${scope[@]}"} \
        --ignore-not-found -o jsonpath='{.metadata.name}{"|"}{.metadata.labels.netpol-demo-prefix}{"|"}{.metadata.labels.netpol-demo-probe-id}') || return 1
      if [[ -n "$owner" && "$owner" != "||" && "$owner" != "$name|$PREFIX|${PROBE_ID:-}" ]]; then
        echo "refusing to $EDGE_MODE unowned $kind $namespace/$name" >&2
        return 1
      fi
      if [[ "$EDGE_MODE" == apply ]]; then
        printf '%s\n' "$manifest" | "${KUBECTL[@]}" apply -f -
      else
        "${KUBECTL[@]}" delete "$resource" "$name" ${scope[@]+"${scope[@]}"} \
          --ignore-not-found --wait=true
      fi
      ;;
  esac
}

edge_policies() {
  edge_policy ciliumnetworkpolicies.cilium.io CiliumNetworkPolicy cilium.io/v2 "$NS_EDGE_SRC" cnp-source "$(cat <<JSON
"specs": [
  {
    "endpointSelector": {"matchLabels": {"k8s:app": "cnp-client"}},
    "egress": [{
      "toEndpoints": [{
        "matchLabels": {"k8s:io.kubernetes.pod.namespace": "$NS_EDGE_DST"},
        "matchExpressions": [{"key": "k8s:app", "operator": "In", "values": ["cnp-server", "cnp-mismatch"]}]
      }],
      "toPorts": [{"ports": [{"port": "8080", "protocol": "TCP"}, {"port": "8081", "protocol": "TCP"}]}]
    }]
  },
  {
    "endpointSelector": {"matchLabels": {"k8s:app": "cnp-client"}},
    "egressDeny": [{
      "toEndpoints": [{"matchLabels": {"k8s:app": "cnp-server", "k8s:netpol-role": "egress-denied", "k8s:io.kubernetes.pod.namespace": "$NS_EDGE_DST"}}],
      "toPorts": [{"ports": [{"port": "8081", "protocol": "TCP"}]}]
    }]
  }
]
JSON
)" || return 1
  edge_policy ciliumnetworkpolicies.cilium.io CiliumNetworkPolicy cilium.io/v2 "$NS_EDGE_DST" cnp-target "$(cat <<JSON
"spec": {
  "endpointSelector": {"matchLabels": {"k8s:app": "cnp-server"}},
  "ingress": [{
    "fromEndpoints": [{"matchLabels": {"k8s:app": "cnp-client", "k8s:io.kubernetes.pod.namespace": "$NS_EDGE_SRC"}}],
    "toPorts": [{"ports": [{"port": "8081", "protocol": "TCP"}, {"port": "8082", "protocol": "TCP"}]}]
  }],
  "ingressDeny": [{
    "fromEndpoints": [{"matchLabels": {"k8s:app": "cnp-client", "k8s:netpol-role": "blocked", "k8s:io.kubernetes.pod.namespace": "$NS_EDGE_SRC"}}],
    "toPorts": [{"ports": [{"port": "8081", "protocol": "TCP"}]}]
  }]
}
JSON
)" || return 1
  edge_policy ciliumnetworkpolicies.cilium.io CiliumNetworkPolicy cilium.io/v2 "$NS_EDGE_DST" cnp-mismatch "$(cat <<JSON
"spec": {
  "endpointSelector": {"matchLabels": {"k8s:app": "cnp-mismatch"}},
  "ingress": [{
    "fromEndpoints": [{"matchLabels": {"k8s:app": "cnp-client", "k8s:io.kubernetes.pod.namespace": "$NS_EDGE_SRC"}}],
    "toPorts": [{"ports": [{"port": "9090", "protocol": "TCP"}]}]
  }]
}
JSON
)" || return 1
  edge_policy ciliumnetworkpolicies.cilium.io CiliumNetworkPolicy cilium.io/v2 "$NS_EDGE_SRC" cnp-empty \
    '"spec": {"endpointSelector": {"matchLabels": {"k8s:app": "cnp-empty"}}, "ingress": [{}], "egress": [{}]}' || return 1
  edge_policy ciliumclusterwidenetworkpolicies.cilium.io CiliumClusterwideNetworkPolicy cilium.io/v2 "" "${PREFIX}-edge-ccnp-empty" "$(cat <<JSON
"spec": {
  "endpointSelector": {"matchLabels": {"k8s:app": "ccnp-empty", "k8s:io.cilium.k8s.namespace.labels.netpol-scenario": "$EDGE_SCENARIO", "k8s:io.cilium.k8s.namespace.labels.netpol-side": "source"}},
  "ingress": [{}], "egress": [{}]
}
JSON
)" || return 1
  edge_policy ciliumclusterwidenetworkpolicies.cilium.io CiliumClusterwideNetworkPolicy cilium.io/v2 "" "${PREFIX}-edge-ccnp" "$(cat <<JSON
"specs": [
  {
    "endpointSelector": {"matchLabels": {"k8s:app": "ccnp-client", "k8s:io.cilium.k8s.namespace.labels.netpol-scenario": "$EDGE_SCENARIO", "k8s:io.cilium.k8s.namespace.labels.netpol-side": "source"}},
    "egress": [{
      "toEndpoints": [{"matchLabels": {"k8s:app": "ccnp-server", "k8s:io.cilium.k8s.namespace.labels.netpol-scenario": "$EDGE_SCENARIO", "k8s:io.cilium.k8s.namespace.labels.netpol-side": "destination"}}],
      "toPorts": [{"ports": [{"port": "9090", "protocol": "TCP"}, {"port": "9091", "protocol": "TCP"}, {"port": "9092", "protocol": "TCP"}]}]
    }],
    "egressDeny": [{
      "toEndpoints": [{"matchLabels": {"k8s:app": "ccnp-server", "k8s:netpol-role": "egress-denied", "k8s:io.cilium.k8s.namespace.labels.netpol-scenario": "$EDGE_SCENARIO", "k8s:io.cilium.k8s.namespace.labels.netpol-side": "destination"}}],
      "toPorts": [{"ports": [{"port": "9091", "protocol": "TCP"}, {"port": "9092", "protocol": "TCP"}]}]
    }]
  },
  {
    "endpointSelector": {"matchLabels": {"k8s:app": "ccnp-server", "k8s:io.cilium.k8s.namespace.labels.netpol-scenario": "$EDGE_SCENARIO", "k8s:io.cilium.k8s.namespace.labels.netpol-side": "destination"}},
    "ingress": [{
      "fromEndpoints": [{"matchLabels": {"k8s:app": "ccnp-client", "k8s:io.cilium.k8s.namespace.labels.netpol-scenario": "$EDGE_SCENARIO", "k8s:io.cilium.k8s.namespace.labels.netpol-side": "source"}}],
      "toPorts": [{"ports": [{"port": "9091", "protocol": "TCP"}, {"port": "9092", "protocol": "TCP"}]}]
    }],
    "ingressDeny": [{
      "fromEndpoints": [{"matchLabels": {"k8s:app": "ccnp-client", "k8s:io.cilium.k8s.namespace.labels.netpol-scenario": "$EDGE_SCENARIO", "k8s:io.cilium.k8s.namespace.labels.netpol-side": "source"}}],
      "toPorts": [{"ports": [{"port": "9091", "protocol": "TCP"}]}]
    }]
  }
]
JSON
)" || return 1
  edge_policy ciliumnetworkpolicies.cilium.io CiliumNetworkPolicy cilium.io/v2 "$NS_EDGE_SRC" cnp-cidr \
    '"spec": {
      "endpointSelector": {"matchLabels": {"k8s:app": "cidr-client"}},
      "egress": [{"toCIDRSet": [{"cidr": "203.0.113.0/24", "except": ["203.0.113.64/26"]}], "toPorts": [{"ports": [{"port": "443", "protocol": "TCP"}]}]}],
      "egressDeny": [{"toCIDR": ["203.0.113.128/25"], "toPorts": [{"ports": [{"port": "443", "protocol": "TCP"}]}]}]
    }' || return 1

  local ports='"ports": [{"protocol": "TCP", "port": 8080}, {"protocol": "TCP", "port": 8081}, {"protocol": "UDP", "port": 5353}, {"protocol": "SCTP", "port": 9000}]'
  edge_policy networkpolicies.networking.k8s.io NetworkPolicy networking.k8s.io/v1 "$NS_EDGE_SRC" authz-source-network "$(cat <<JSON
"spec": {
  "podSelector": {"matchLabels": {"app": "authz-client"}}, "policyTypes": ["Egress"],
  "egress": [{
    "to": [{
      "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "$NS_EDGE_DST"}},
      "podSelector": {"matchExpressions": [{"key": "app", "operator": "In", "values": ["authz-server", "authz-no-tcp", "authz-closed", "authz-identity"]}]}
    }], $ports
  }]
}
JSON
)" || return 1
  edge_policy networkpolicies.networking.k8s.io NetworkPolicy networking.k8s.io/v1 "$NS_EDGE_DST" authz-target-network "$(cat <<JSON
"spec": {
  "podSelector": {"matchExpressions": [{"key": "app", "operator": "In", "values": ["authz-server", "authz-no-tcp", "authz-identity"]}]}, "policyTypes": ["Ingress"],
  "ingress": [{
    "from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "$NS_EDGE_SRC"}}, "podSelector": {"matchLabels": {"app": "authz-client"}}}],
    $ports
  }]
}
JSON
)" || return 1
  edge_policy networkpolicies.networking.k8s.io NetworkPolicy networking.k8s.io/v1 "$NS_EDGE_DST" authz-closed-network "$(cat <<JSON
"spec": {
  "podSelector": {"matchLabels": {"app": "authz-closed"}}, "policyTypes": ["Ingress"],
  "ingress": [{
    "from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "$NS_EDGE_SRC"}}, "podSelector": {"matchLabels": {"app": "authz-client"}}}],
    "ports": [{"protocol": "TCP", "port": 8080}]
  }]
}
JSON
)" || return 1
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" authz-ports-allow \
    '"spec": {"selector": {"matchLabels": {"app": "authz-server"}}, "action": "ALLOW", "rules": [{"to": [{"operation": {"ports": ["8080", "8081"]}}]}]}' || return 1
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" authz-ports-deny \
    '"spec": {"selector": {"matchLabels": {"app": "authz-server"}}, "action": "DENY", "rules": [{"to": [{"operation": {"ports": ["8081"]}}]}]}' || return 1
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" authz-no-tcp \
    '"spec": {"selector": {"matchLabels": {"app": "authz-no-tcp"}}, "action": "ALLOW", "rules": []}' || return 1
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" authz-closed \
    '"spec": {"selector": {"matchLabels": {"app": "authz-closed"}}, "action": "ALLOW", "rules": []}' || return 1
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_SRC" authz-client-ingress-deny \
    '"spec": {"selector": {"matchLabels": {"app": "authz-client"}}, "action": "DENY", "rules": [{}]}'
}

edge_probe_policy() {
  case "$PROBE" in
    identity)
      edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 \
        "$NS_EDGE_DST" "probe-identity-$PROBE_ID" "$(cat <<JSON
"spec": {
  "selector": {"matchLabels": {"app": "authz-identity"}}, "action": "ALLOW",
  "rules": [{"from": [{"source": {"namespaces": ["$NS_EDGE_SRC"]}}], "to": [{"operation": {"ports": ["8080", "8081"]}}]}]
}
JSON
)"
      ;;
    unsupported)
      edge_policy ciliumnetworkpolicies.cilium.io CiliumNetworkPolicy cilium.io/v2 \
        "$NS_EDGE_SRC" "probe-unsupported-$PROBE_ID" \
        '"spec": {"endpointSelector": {"matchLabels": {"k8s:app": "uncertain-client"}}, "egress": [{"toFQDNs": [{"matchName": "fixture.invalid"}], "toPorts": [{"ports": [{"port": "443", "protocol": "TCP"}]}]}]}'
      ;;
  esac
}

check_edge_fixtures() {
  local failures=0 namespace side name app role
  for side in source destination other; do
    case "$side" in
      source) namespace="$NS_EDGE_SRC" ;;
      destination) namespace="$NS_EDGE_DST" ;;
      other) namespace="$NS_EDGE_OTHER" ;;
    esac
    check_resource_value "scenario namespace $namespace labels" "$PREFIX|$EDGE_SCENARIO|$side" \
      "${KUBECTL[@]}" get namespace "$namespace" \
      -o jsonpath='{.metadata.labels.netpol-demo-prefix}{"|"}{.metadata.labels.netpol-scenario}{"|"}{.metadata.labels.netpol-side}' || failures=$((failures + 1))
  done
  while read -r namespace name app role; do
    check_resource_value "scenario pod $namespace/$name labels and readiness" "$PREFIX|$app|$role|True" \
      "${KUBECTL[@]}" get pod -n "$namespace" "$name" \
      -o jsonpath='{.metadata.labels.netpol-demo-prefix}{"|"}{.metadata.labels.app}{"|"}{.metadata.labels.netpol-role}{"|"}{.status.conditions[?(@.type=="Ready")].status}' || failures=$((failures + 1))
  done < <(edge_pods)
  EDGE_MODE=check edge_policies || failures=$((failures + 1))
  for namespace in "$NS_EDGE_SRC" "$NS_EDGE_DST"; do
    check_resource_absent "no uncertainty probes remain in $namespace" \
      "${KUBECTL[@]}" get ciliumnetworkpolicies.cilium.io,authorizationpolicies.security.istio.io \
      -n "$namespace" -l "netpol-demo-prefix=$PREFIX,netpol-demo-probe" -o name || failures=$((failures + 1))
  done
  (( failures == 0 ))
}

apply_edge_fixtures() {
  local namespace side name app role
  for side in source destination other; do
    case "$side" in
      source) namespace="$NS_EDGE_SRC" ;;
      destination) namespace="$NS_EDGE_DST" ;;
      other) namespace="$NS_EDGE_OTHER" ;;
    esac
    "${KUBECTL[@]}" apply -f - <<JSON
{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"$namespace","labels":{"netpol-demo":"true","netpol-demo-prefix":"$PREFIX","netpol-scenario":"$EDGE_SCENARIO","netpol-side":"$side"}}}
JSON
  done
  while read -r namespace name app role; do
    "${KUBECTL[@]}" apply -f - <<JSON
{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"$name","namespace":"$namespace","labels":{"netpol-demo-prefix":"$PREFIX","app":"$app","netpol-role":"$role"}},
  "spec":{"containers":[{"name":"idle","image":"$IMAGE","imagePullPolicy":"IfNotPresent","command":["sh","-c","while true; do sleep 3600; done"],"resources":{"requests":{"cpu":"5m","memory":"8Mi"}}}]}
}
JSON
  done < <(edge_pods)
  EDGE_MODE=apply edge_policies || return 1
  if (( WAIT == 1 )); then
    for namespace in "$NS_EDGE_SRC" "$NS_EDGE_DST" "$NS_EDGE_OTHER"; do
      "${KUBECTL[@]}" wait --for=condition=Ready pod --all -n "$namespace" --timeout="$TIMEOUT" || return 1
    done
  fi
}
