#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of K9s

# Sourced by the demo entry point; all Kubernetes access uses its explicit
# KUBECTL array. Uncertainty is scoped to the pairs a policy can affect, so the
# ordinary topology may contain uncertain rules; the identity and unsupported
# probes stay opt-in so their suites prove scoping against a fixed topology.
#
# The source and destination namespaces are enrolled in the Istio ambient mesh
# (istio.io/dataplane-mode=ambient). AuthorizationPolicy only applies to mesh
# workloads, so the fixtures also carry an opted-out pod and a pod whose stale
# sidecar status annotation makes its enrollment unknown.

# Columns: namespace, pod, app label, netpol-role label, mesh fixture. The mesh
# fixture is "-" (inherits the namespace), "opt-out" (istio.io/dataplane-mode
# =none) or "stale-sidecar" (sidecar.istio.io/status without istio-proxy).
edge_pods() {
  cat <<PODS
$NS_EDGE_SRC cnp-client cnp-client allowed -
$NS_EDGE_SRC cnp-blocked cnp-client blocked -
$NS_EDGE_SRC ccnp-client ccnp-client allowed -
$NS_EDGE_SRC cnp-empty cnp-empty empty -
$NS_EDGE_SRC ccnp-empty ccnp-empty empty -
$NS_EDGE_SRC cidr-client cidr-client allowed -
$NS_EDGE_SRC authz-client authz-client allowed -
$NS_EDGE_SRC uncertain-client uncertain-client probe -
$NS_EDGE_SRC native-client native-client allowed -
$NS_EDGE_SRC native-local native-local allowed -
$NS_EDGE_SRC cnp-observe cnp-observe allowed -
$NS_EDGE_DST cnp-server cnp-server allowed -
$NS_EDGE_DST cnp-denied cnp-server egress-denied -
$NS_EDGE_DST cnp-mismatch cnp-mismatch mismatch -
$NS_EDGE_DST ccnp-server ccnp-server allowed -
$NS_EDGE_DST ccnp-denied ccnp-server egress-denied -
$NS_EDGE_DST authz-server authz-server allowed -
$NS_EDGE_DST authz-no-tcp authz-no-tcp restricted -
$NS_EDGE_DST authz-closed authz-closed restricted -
$NS_EDGE_DST authz-identity authz-identity probe -
$NS_EDGE_DST authz-unenrolled authz-unenrolled restricted opt-out
$NS_EDGE_DST authz-unknown authz-unknown restricted stale-sidecar
$NS_EDGE_DST l7-server l7-server l7 -
$NS_EDGE_DST native-target native-target - -
$NS_EDGE_DST native-blocked native-target blocked -
$NS_EDGE_DST native-excluded native-target allowed selector-excluded
$NS_EDGE_DST native-local-lookalike native-local allowed -
$NS_EDGE_DST authz-default authz-default allowed -
$NS_EDGE_DST authz-denyonly authz-denyonly allowed -
$NS_EDGE_DST authz-noenforce authz-noenforce allowed -
$NS_EDGE_DST authz-l7-allow authz-l7-allow probe -
$NS_EDGE_DST authz-l7-deny authz-l7-deny probe -
$NS_EDGE_DST authz-request-allow authz-request-allow probe -
$NS_EDGE_DST authz-request-deny authz-request-deny probe -
$NS_EDGE_OTHER control control control -
$NS_EDGE_OTHER native-lookalike native-target allowed -
$NS_EDGE_OTHER cnp-scope cnp-observe allowed -
$NS_EDGE_OTHER authz-inject-annotation authz-injection restricted inject-annotation
$NS_EDGE_OTHER authz-inject-label authz-injection restricted inject-label
$NS_EDGE_OTHER authz-inject-optout authz-injection restricted inject-optout
PODS
}

edge_probe_types() {
  printf '%s\n' identity unsupported cilium-features cilium-rejected istio-features istio-custom istio-targetrefs istio-root
}

# edge_namespace_mesh prints the dataplane mode label of a fixture namespace.
edge_namespace_mesh() {
  case "$1" in
    source|destination) printf 'ambient' ;;
  esac
}

# edge_pod_mesh prints the expected dataplane label and sidecar status of a
# fixture pod, separated by "|".
edge_pod_mesh() {
  case "$1" in
    opt-out) printf 'none|' ;;
    stale-sidecar) printf '|%s' "$EDGE_STALE_SIDECAR_STATUS" ;;
    *) printf '|' ;;
  esac
}

EDGE_STALE_SIDECAR_STATUS='{"containers":["istio-proxy"]}'

edge_pod_extra() {
  case "$1" in
    selector-excluded) printf '||true' ;;
    inject-annotation) printf '|true|' ;;
    inject-label) printf 'true|false|' ;;
    inject-optout) printf 'false|true|' ;;
    *) printf '||' ;;
  esac
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
  local annotations="${7:-}" manifest expected actual owner probe_labels="" scope=()
  [[ -n "$annotations" ]] || annotations='{}'
  [[ -n "$namespace" ]] && scope=(-n "$namespace")
  if [[ -n "${PROBE:-}" ]]; then
    probe_labels=", \"netpol-demo-probe\": \"$PROBE\", \"netpol-demo-probe-id\": \"$PROBE_ID\""
  fi
  manifest=$(cat <<JSON
{
  "apiVersion": "$version", "kind": "$kind",
  "metadata": {
    "name": "$name", "namespace": "$namespace",
    "annotations": $annotations,
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
        -o jsonpath='{.metadata.labels.netpol-demo-prefix}{"|"}{.metadata.labels.netpol-demo-edge}{"|"}{.metadata.labels.netpol-demo-probe}{"|"}{.metadata.labels.netpol-demo-probe-id}' || return 1
      expected=$(printf '%s\n' "$manifest" | "${KUBECTL[@]}" create \
        --dry-run=client --validate=false -f - -o jsonpath='{.metadata.annotations.istio\.io/dry-run}') || return 1
      check_resource_value "$kind $namespace/$name dry-run annotation" "$expected" \
        "${KUBECTL[@]}" get "$resource" "$name" ${scope[@]+"${scope[@]}"} \
        -o jsonpath='{.metadata.annotations.istio\.io/dry-run}'
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
      "podSelector": {"matchExpressions": [{"key": "app", "operator": "In", "values": ["authz-server", "authz-no-tcp", "authz-closed", "authz-identity", "authz-unenrolled", "authz-unknown", "authz-default", "authz-denyonly", "authz-noenforce", "authz-l7-allow", "authz-l7-deny", "authz-request-allow", "authz-request-deny"]}]}
    }], $ports
  }]
}
JSON
)" || return 1
  edge_policy networkpolicies.networking.k8s.io NetworkPolicy networking.k8s.io/v1 "$NS_EDGE_DST" authz-target-network "$(cat <<JSON
"spec": {
  "podSelector": {"matchExpressions": [{"key": "app", "operator": "In", "values": ["authz-server", "authz-no-tcp", "authz-identity", "authz-unenrolled", "authz-unknown"]}]}, "policyTypes": ["Ingress"],
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
    '"spec": {"selector": {"matchLabels": {"app": "authz-client"}}, "action": "DENY", "rules": [{}]}' || return 1
  # Not enforced: the selected pod opts out of the mesh.
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" authz-unenrolled \
    '"spec": {"selector": {"matchLabels": {"app": "authz-unenrolled"}}, "action": "ALLOW", "rules": []}' || return 1
  # Enforcement is uncertain: the selected pod has a stale sidecar status.
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" authz-unknown \
    '"spec": {"selector": {"matchLabels": {"app": "authz-unknown"}}, "action": "ALLOW", "rules": [{"to": [{"operation": {"ports": ["8080"]}}]}]}' || return 1
  # An ordinary uncertain rule: only pairs it can match become Partial Data.
  edge_policy ciliumnetworkpolicies.cilium.io CiliumNetworkPolicy cilium.io/v2 "$NS_EDGE_DST" cnp-l7 "$(cat <<JSON
"spec": {
  "endpointSelector": {"matchLabels": {"k8s:app": "l7-server"}},
  "ingress": [{
    "fromEndpoints": [{"matchLabels": {"k8s:app": "control", "k8s:io.kubernetes.pod.namespace": "$NS_EDGE_OTHER"}}],
    "toPorts": [{"ports": [{"port": "8080", "protocol": "TCP"}], "rules": {"http": [{"method": "GET"}]}}]
  }]
}
JSON
)" || return 1
  edge_feature_policies
}

edge_feature_policies() {
  local ports='"ports":[{"port":8080,"protocol":"TCP"},{"port":8081,"protocol":"TCP"},{"port":5353,"protocol":"UDP"},{"port":9000,"protocol":"SCTP"}]'
  edge_policy networkpolicies.networking.k8s.io NetworkPolicy networking.k8s.io/v1 "$NS_EDGE_SRC" native-source "$(cat <<JSON
"spec":{"podSelector":{"matchLabels":{"app":"native-client"}},"policyTypes":["Egress"],"egress":[{
  "to":[
    {"podSelector":{"matchLabels":{"app":"native-local"}}},
    {"namespaceSelector":{"matchLabels":{"netpol-scenario":"$EDGE_SCENARIO"},"matchExpressions":[{"key":"netpol-side","operator":"In","values":["destination"]}]},"podSelector":{"matchExpressions":[{"key":"app","operator":"In","values":["native-target"]},{"key":"netpol-role","operator":"NotIn","values":["blocked"]},{"key":"app","operator":"Exists"},{"key":"netpol-excluded","operator":"DoesNotExist"}]}}
  ],"ports":[{"port":8000,"endPort":8002,"protocol":"TCP"},{"port":5353,"protocol":"UDP"},{"port":9000,"protocol":"SCTP"}]
}]}
JSON
)" || return 1
  edge_policy networkpolicies.networking.k8s.io NetworkPolicy networking.k8s.io/v1 "$NS_EDGE_DST" native-target "$(cat <<JSON
"spec":{"podSelector":{"matchLabels":{"app":"native-target"}},"policyTypes":["Ingress"],"ingress":[{
  "from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"$NS_EDGE_SRC"}},"podSelector":{"matchLabels":{"app":"native-client"}}}],
  "ports":[{"port":8001,"endPort":8003,"protocol":"TCP"},{"port":5353,"protocol":"UDP"}]
}]}
JSON
)" || return 1
  local namespace
  for namespace in "$NS_EDGE_SRC" "$NS_EDGE_OTHER"; do
    edge_policy networkpolicies.networking.k8s.io NetworkPolicy networking.k8s.io/v1 "$namespace" cnp-observe-network \
      "\"spec\":{\"podSelector\":{\"matchLabels\":{\"app\":\"cnp-observe\"}},\"policyTypes\":[\"Egress\"],\"egress\":[{$ports}]}" || return 1
  done
  edge_policy ciliumnetworkpolicies.cilium.io CiliumNetworkPolicy cilium.io/v2 "$NS_EDGE_SRC" cnp-observe "$(cat <<JSON
"spec":{"endpointSelector":{"matchLabels":{"k8s:app":"cnp-observe"}},"enableDefaultDeny":{"egress":false},"egress":[
  {"toEndpoints":[{"matchLabels":{"k8s:io.kubernetes.pod.namespace":"$NS_EDGE_OTHER","any:netpol-role":"other","k8s:netpol-role":"control"}}],"toPorts":[{"ports":[{"port":"80","protocol":"TCP"}]}]},
  {"toEndpoints":[{"matchLabels":{"k8s:io.kubernetes.pod.namespace":"$NS_EDGE_OTHER","any:netpol-role":"control","k8s:netpol-role":"control"}}],"toPorts":[{"ports":[{"port":"8080","protocol":"TCP"}]}]}
]},
"specs":[{"endpointSelector":{"matchLabels":{"k8s:app":"cnp-observe"}},"enableDefaultDeny":{"egress":false},"egressDeny":[
  {"toEndpoints":[{"matchLabels":{"k8s:app":"control","k8s:io.kubernetes.pod.namespace":"$NS_EDGE_OTHER"}}],"toPorts":[{"ports":[{"port":"8081","protocol":"TCP"}]}]}
]}]
JSON
)" || return 1
  edge_policy networkpolicies.networking.k8s.io NetworkPolicy networking.k8s.io/v1 "$NS_EDGE_DST" authz-feature-network "$(cat <<JSON
"spec":{"podSelector":{"matchExpressions":[{"key":"app","operator":"In","values":["authz-default","authz-denyonly","authz-noenforce","authz-l7-allow","authz-l7-deny","authz-request-allow","authz-request-deny"]}]},"policyTypes":["Ingress"],"ingress":[{
  "from":[
    {"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"$NS_EDGE_SRC"}},"podSelector":{"matchLabels":{"app":"authz-client"}}},
    {"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"$NS_EDGE_OTHER"}},"podSelector":{"matchLabels":{"app":"control"}}}
  ],$ports
}]}
JSON
)" || return 1
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" authz-default \
    '"spec":{"selector":{"matchLabels":{"app":"authz-default"}},"rules":[{}]}' || return 1
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" authz-denyonly \
    '"spec":{"selector":{"matchLabels":{"app":"authz-denyonly"}},"action":"DENY","rules":[{"to":[{"operation":{"ports":["8081"]}}]}]}' || return 1
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" authz-audit \
    '"spec":{"selector":{"matchLabels":{"app":"authz-noenforce"}},"action":"AUDIT","rules":[]}' || return 1
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" authz-dryrun \
    '"spec":{"selector":{"matchLabels":{"app":"authz-noenforce"}},"action":"DENY","rules":[{}]}' '{"istio.io/dry-run":"true"}' || return 1
  edge_policy networkpolicies.networking.k8s.io NetworkPolicy networking.k8s.io/v1 "$NS_EDGE_OTHER" authz-injection-network \
    '"spec":{"podSelector":{"matchLabels":{"app":"authz-injection"}},"policyTypes":["Ingress"],"ingress":[{"from":[{"podSelector":{"matchLabels":{"app":"control"}}}],"ports":[{"port":8080,"protocol":"TCP"}]}]}' || return 1
  edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_OTHER" authz-injection \
    '"spec":{"selector":{"matchLabels":{"app":"authz-injection"}},"rules":[]}'
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
    cilium-features)
      edge_policy ciliumnetworkpolicies.cilium.io CiliumNetworkPolicy cilium.io/v2 "$NS_EDGE_SRC" "probe-cilium-features-$PROBE_ID" "$(cat <<JSON
"spec":{"endpointSelector":{"matchLabels":{"k8s:app":"uncertain-client"}},"egress":[
  {"toRequires":[{"matchLabels":{"env":"prod"}}]},
  {"toGroups":[{"aws":{"labels":{"env":"prod"}}}]},
  {"toCIDRSet":[{"cidrGroupSelector":{"matchLabels":{"env":"prod"}}}]},
  {"toEndpoints":[{"matchLabels":{"io.cilium.k8s.policy.unmodeled":"value"}}]},
  {"toEndpoints":[{"matchLabels":{"k8s:app":"control","k8s:io.kubernetes.pod.namespace":"$NS_EDGE_OTHER"}}],"toPorts":[{"ports":[{"port":"443","protocol":"TCP"}],"originatingTLS":{"secret":{"name":"tls"}}}]}
]}
JSON
)"
      ;;
    cilium-rejected)
      edge_policy ciliumnetworkpolicies.cilium.io CiliumNetworkPolicy cilium.io/v2 "$NS_EDGE_SRC" "probe-cilium-rejected-$PROBE_ID" \
        '"spec":{"endpointSelector":{"matchLabels":{"k8s:app":"uncertain-client"}},"egress":[{"toPorts":[{"ports":[{"port":"443","protocol":"TCP"}]}]}]},"specs":[{"endpointSelector":{"matchLabels":{"k8s:app":"absent-invalid-sibling"}},"egress":[{"toPorts":[{"ports":[{"port":"70000","protocol":"TCP"}]}]}]}]'
      ;;
    istio-features)
      local class action predicate rules failures=0
      for class in l7 request; do
        for action in ALLOW DENY; do
          if [[ "$class" == l7 ]]; then
            rules="[{\"from\":[{\"source\":{\"namespaces\":[\"$NS_EDGE_SRC\"]}}],\"to\":[{\"operation\":{\"ports\":[\"8080\"],\"hosts\":[\"api.example\"],\"notHosts\":[\"admin.example\"],\"methods\":[\"GET\"],\"notMethods\":[\"DELETE\"],\"paths\":[\"/public*\"],\"notPaths\":[\"/private*\"]}}]}]"
          else
            rules='['
            for predicate in '"notRequestPrincipals":["issuer/blocked"]' '"notRemoteIpBlocks":["192.0.2.0/24"]'; do
              [[ "$rules" == '[' ]] || rules+=,
              rules+="{\"from\":[{\"source\":{\"namespaces\":[\"$NS_EDGE_SRC\"],$predicate}}],\"to\":[{\"operation\":{\"ports\":[\"8080\"]}}]}"
            done
            rules+=']'
          fi
          local lower
          lower=$(printf '%s' "$action" | tr '[:upper:]' '[:lower:]')
          edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" "probe-istio-$class-$lower-$PROBE_ID" \
            "\"spec\":{\"selector\":{\"matchLabels\":{\"app\":\"authz-$class-$lower\"}},\"action\":\"$action\",\"rules\":$rules}" || {
              [[ "$EDGE_MODE" == delete ]] || return 1
              failures=1
            }
        done
      done
      return "$failures"
      ;;
    istio-custom)
      edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" "probe-istio-custom-$PROBE_ID" \
        "\"spec\":{\"selector\":{\"matchLabels\":{\"app\":\"authz-default\"}},\"action\":\"CUSTOM\",\"provider\":{\"name\":\"fixture-provider\"},\"rules\":[{\"from\":[{\"source\":{\"namespaces\":[\"$NS_EDGE_SRC\"]}}],\"to\":[{\"operation\":{\"ports\":[\"8080\"]}}]}]}"
      ;;
    istio-targetrefs)
      edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 "$NS_EDGE_DST" "probe-istio-targetrefs-$PROBE_ID" \
        '"spec":{"targetRefs":[{"group":"","kind":"Service","name":"unresolved-fixture"}],"action":"ALLOW","rules":[]}'
      ;;
    istio-root)
      edge_policy authorizationpolicies.security.istio.io AuthorizationPolicy security.istio.io/v1 istio-system "probe-istio-root-$PROBE_ID" \
        "\"spec\":{\"selector\":{\"matchLabels\":{\"app\":\"authz-identity\",\"netpol-demo-prefix\":\"$PREFIX\"}},\"action\":\"ALLOW\",\"rules\":[{\"to\":[{\"operation\":{\"ports\":[\"8080\"]}}]}]}"
      ;;
    *) echo "unknown edge probe: $PROBE" >&2; return 2 ;;
  esac
}

check_edge_fixtures() {
  local failures=0 namespace side name app role mesh
  check_resource "Istio default root fixture namespace" "${KUBECTL[@]}" get namespace istio-system || failures=$((failures + 1))
  for side in source destination other; do
    case "$side" in
      source) namespace="$NS_EDGE_SRC" ;;
      destination) namespace="$NS_EDGE_DST" ;;
      other) namespace="$NS_EDGE_OTHER" ;;
    esac
    check_resource_value "scenario namespace $namespace labels" "$PREFIX|$EDGE_SCENARIO|$side|$(edge_namespace_mesh "$side")" \
      "${KUBECTL[@]}" get namespace "$namespace" \
      -o jsonpath='{.metadata.labels.netpol-demo-prefix}{"|"}{.metadata.labels.netpol-scenario}{"|"}{.metadata.labels.netpol-side}{"|"}{.metadata.labels.istio\.io/dataplane-mode}' || failures=$((failures + 1))
  done
  while read -r namespace name app role mesh; do
    [[ "$role" != - ]] || role=""
    check_resource_value "scenario pod $namespace/$name labels, mesh fixture and readiness" "$PREFIX|$app|$role|$(edge_pod_mesh "$mesh")|$(edge_pod_extra "$mesh")|True" \
      "${KUBECTL[@]}" get pod -n "$namespace" "$name" \
      -o jsonpath='{.metadata.labels.netpol-demo-prefix}{"|"}{.metadata.labels.app}{"|"}{.metadata.labels.netpol-role}{"|"}{.metadata.labels.istio\.io/dataplane-mode}{"|"}{.metadata.annotations.sidecar\.istio\.io/status}{"|"}{.metadata.labels.sidecar\.istio\.io/inject}{"|"}{.metadata.annotations.sidecar\.istio\.io/inject}{"|"}{.metadata.labels.netpol-excluded}{"|"}{.status.conditions[?(@.type=="Ready")].status}' || failures=$((failures + 1))
  done < <(edge_pods)
  EDGE_MODE=check edge_policies || failures=$((failures + 1))
  for namespace in "$NS_EDGE_SRC" "$NS_EDGE_DST" "$NS_EDGE_OTHER" istio-system; do
    check_resource_absent "no uncertainty probes remain in $namespace" \
      "${KUBECTL[@]}" get ciliumnetworkpolicies.cilium.io,authorizationpolicies.security.istio.io \
      -n "$namespace" -l "netpol-demo-prefix=$PREFIX,netpol-demo-probe" -o name || failures=$((failures + 1))
  done
  (( failures == 0 ))
}

apply_edge_fixtures() {
  local namespace side name app role mesh mode labels annotations
  # Preserve a shared root namespace; this creates metadata only, never Istio.
  if ! "${KUBECTL[@]}" get namespace istio-system >/dev/null 2>&1; then
    "${KUBECTL[@]}" create namespace istio-system || return 1
  fi
  for side in source destination other; do
    case "$side" in
      source) namespace="$NS_EDGE_SRC" ;;
      destination) namespace="$NS_EDGE_DST" ;;
      other) namespace="$NS_EDGE_OTHER" ;;
    esac
    labels=""
    mode="$(edge_namespace_mesh "$side")"
    [[ -n "$mode" ]] && labels=",\"istio.io/dataplane-mode\":\"$mode\""
    "${KUBECTL[@]}" apply -f - <<JSON
{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"$namespace","labels":{"netpol-demo":"true","netpol-demo-prefix":"$PREFIX","netpol-scenario":"$EDGE_SCENARIO","netpol-side":"$side"$labels}}}
JSON
  done
  while read -r namespace name app role mesh; do
    labels=""
    annotations="{}"
    case "$mesh" in
      opt-out) labels=',"istio.io/dataplane-mode":"none"' ;;
      stale-sidecar) annotations="{\"sidecar.istio.io/status\":$(printf '%s' "$EDGE_STALE_SIDECAR_STATUS" | sed 's/"/\\"/g; s/^/"/; s/$/"/')}" ;;
      selector-excluded) labels=',"netpol-excluded":"true"' ;;
      inject-annotation) annotations='{"sidecar.istio.io/inject":"true"}' ;;
      inject-label) labels=',"sidecar.istio.io/inject":"true"'; annotations='{"sidecar.istio.io/inject":"false"}' ;;
      inject-optout) labels=',"sidecar.istio.io/inject":"false"'; annotations='{"sidecar.istio.io/inject":"true"}' ;;
    esac
    [[ "$role" == - ]] || labels+=",\"netpol-role\":\"$role\""
    "${KUBECTL[@]}" apply -f - <<JSON
{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"$name","namespace":"$namespace","annotations":$annotations,"labels":{"netpol-demo-prefix":"$PREFIX","app":"$app"$labels}},
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
