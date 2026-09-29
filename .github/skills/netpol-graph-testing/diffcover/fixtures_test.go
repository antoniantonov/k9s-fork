// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/derailed/k9s/internal/netpol"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	fixtureSource = "fixture-edge-src"
	fixtureTarget = "fixture-edge-dst"
	fixtureOther  = "fixture-edge-other"
	fixtureFull   = "SCTP/9000, TCP/8080, TCP/8081, UDP/5353"
	fixtureNonTCP = "SCTP/9000, UDP/5353"
)

func generatedFixtureSnapshot(t *testing.T, probe string) netpol.Snapshot {
	t.Helper()
	output, err := bashScript(t, `source "$LIB"
PREFIX=fixture
NS_EDGE_SRC=fixture-edge-src
NS_EDGE_DST=fixture-edge-dst
NS_EDGE_OTHER=fixture-edge-other
EDGE_SCENARIO=fixture-edges
IMAGE=fixture-image
WAIT=0
PROBE=""
PROBE_ID=""
fixture_kubectl() { if [[ "$1" == apply ]]; then cat; fi; }
KUBECTL=(fixture_kubectl)
apply_edge_fixtures || exit
if [[ -n "$FIXTURE_PROBE" ]]; then
  PROBE="$FIXTURE_PROBE"
  PROBE_ID=fixture-run
  EDGE_MODE=apply
  edge_probe_policy
fi`, "LIB="+edgeLibrary(t), "FIXTURE_PROBE="+probe)
	if err != nil {
		t.Fatalf("render deployable fixtures: %v\n%s", err, output)
	}
	snapshot := netpol.Snapshot{}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		var object unstructured.Unstructured
		if err := object.UnmarshalJSON(raw); err != nil {
			t.Fatal(err)
		}
		object.SetUID(types.UID(object.GetKind() + "/" + object.GetNamespace() + "/" + object.GetName()))
		object.SetResourceVersion("1")
		switch object.GetKind() {
		case "Namespace":
			namespace := decodeFixture[corev1.Namespace](t, raw)
			namespace.Labels["kubernetes.io/metadata.name"] = namespace.Name
			snapshot.Namespaces = append(snapshot.Namespaces, namespace)
		case "Pod":
			pod := decodeFixture[corev1.Pod](t, raw)
			pod.Status.Phase = corev1.PodRunning
			pod.Status.PodIP = fmt.Sprintf("10.244.0.%d", len(snapshot.Pods)+1)
			pod.UID = object.GetUID()
			snapshot.Pods = append(snapshot.Pods, pod)
		case "NetworkPolicy":
			snapshot.NetworkPolicies = append(snapshot.NetworkPolicies, decodeFixture[netv1.NetworkPolicy](t, raw))
		case "CiliumNetworkPolicy":
			snapshot.CiliumNetworkPolicies = append(snapshot.CiliumNetworkPolicies, object)
		case "CiliumClusterwideNetworkPolicy":
			snapshot.CiliumClusterwideNetworkPolicies = append(snapshot.CiliumClusterwideNetworkPolicies, object)
		case "AuthorizationPolicy":
			snapshot.IstioAuthorizationPolicies = append(snapshot.IstioAuthorizationPolicies, object)
		default:
			t.Fatalf("unexpected generated kind %s", object.GetKind())
		}
	}
	return snapshot
}

func decodeFixture[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

type fixtureRowContract struct {
	name, subject, namespace, peer, peerNamespace string
	direction                                     netpol.Direction
	state                                         netpol.AccessState
	ports                                         string
	peerMatches, opposite                         bool
	warnings                                      []string
}

func assertGeneratedFixtureRows(t *testing.T, probe string, rows []fixtureRowContract) {
	t.Helper()
	snapshot := generatedFixtureSnapshot(t, probe)
	evaluator := netpol.NewEvaluator()
	for index := range rows {
		contract := &rows[index]
		t.Run(contract.name, func(t *testing.T) {
			result, err := evaluator.EvaluateSubject(netpol.SubjectRef{
				Kind: netpol.SubjectPod, Namespace: contract.namespace, Name: contract.subject,
			}, snapshot, netpol.Options{})
			if err != nil {
				t.Fatal(err)
			}
			applicability := evaluator.DirectionApplicability(result, contract.direction, sets.New(netpol.PrimitivePod))
			for rowIndex := range applicability {
				row := &applicability[rowIndex]
				if row.Primitive.Ref.Name != contract.peer || row.Primitive.Ref.Namespace != contract.peerNamespace {
					continue
				}
				ports := []string{}
				for _, permission := range row.Permissions {
					ports = append(ports, permission.String())
				}
				actual := strings.Join(ports, ", ")
				if actual == "" {
					actual = "no ports"
				}
				if row.EffectiveState != contract.state || actual != contract.ports ||
					row.PeerMatches != contract.peerMatches || row.OppositeSideAllows != contract.opposite {
					t.Fatalf("generated fixture row: got %s %q %t/%t, want %s %q %t/%t; warnings=%v",
						row.EffectiveState, actual, row.PeerMatches, row.OppositeSideAllows,
						contract.state, contract.ports, contract.peerMatches, contract.opposite, row.Primitive.Warnings)
				}
				for _, warning := range contract.warnings {
					if !slices.Contains(result.Warnings, warning) {
						t.Fatalf("missing exact fixture diagnostic %q; got %v", warning, result.Warnings)
					}
				}
				if contract.state != netpol.AccessPartialData && len(row.Primitive.Warnings) > 0 {
					t.Fatalf("definitive fixture control has warnings: %v", row.Primitive.Warnings)
				}
				return
			}
			t.Fatalf("generated fixture peer %s/%s was absent", contract.peerNamespace, contract.peer)
		})
	}
}

func TestGeneratedStableFixtureSemantics(t *testing.T) {
	rows := []fixtureRowContract{
		{"native-range", "native-client", fixtureSource, "native-target", fixtureTarget, netpol.Egress, netpol.AccessAllowed, "TCP/8001-8002, UDP/5353", true, true, nil},
		{"native-local", "native-client", fixtureSource, "native-local", fixtureSource, netpol.Egress, netpol.AccessAllowed, "SCTP/9000, TCP/8000-8002, UDP/5353", true, true, nil},
		{"native-local-scope", "native-client", fixtureSource, "native-local-lookalike", fixtureTarget, netpol.Egress, netpol.AccessDisallowed, "no ports", false, false, nil},
		{"native-notin", "native-client", fixtureSource, "native-blocked", fixtureTarget, netpol.Egress, netpol.AccessDisallowed, "no ports", false, false, nil},
		{"native-doesnotexist", "native-client", fixtureSource, "native-excluded", fixtureTarget, netpol.Egress, netpol.AccessDisallowed, "no ports", false, false, nil},
		{"native-and", "native-client", fixtureSource, "native-lookalike", fixtureOther, netpol.Egress, netpol.AccessDisallowed, "no ports", false, false, nil},
		{"cilium-observe", "cnp-observe", fixtureSource, "control", fixtureOther, netpol.Egress, netpol.AccessAllowed, "SCTP/9000, TCP/8080, UDP/5353", true, true, nil},
		{"cilium-namespace", "cnp-scope", fixtureOther, "control", fixtureOther, netpol.Egress, netpol.AccessAllowed, fixtureFull, true, true, nil},
		{"istio-default", "authz-default", fixtureTarget, "authz-client", fixtureSource, netpol.Ingress, netpol.AccessAllowed, fixtureFull, true, true, nil},
		{"istio-denyonly", "authz-denyonly", fixtureTarget, "authz-client", fixtureSource, netpol.Ingress, netpol.AccessAllowed, "SCTP/9000, TCP/8080, UDP/5353", true, true, nil},
		{"istio-noenforce", "authz-noenforce", fixtureTarget, "authz-client", fixtureSource, netpol.Ingress, netpol.AccessAllowed, fixtureFull, true, true, nil},
		{"injection-optout", "authz-inject-optout", fixtureOther, "control", fixtureOther, netpol.Ingress, netpol.AccessAllowed, "TCP/8080", true, true, nil},
	}
	for _, pod := range []string{"authz-inject-annotation", "authz-inject-label"} {
		warning := fmt.Sprintf("Istio AuthorizationPolicy enforcement for pod %s/%s is uncertain: sidecar injection is enabled for pod %s/%s, but it has no istio-proxy container", fixtureOther, pod, fixtureOther, pod)
		rows = append(rows, fixtureRowContract{pod, pod, fixtureOther, "control", fixtureOther, netpol.Ingress, netpol.AccessPartialData, "no ports", true, false, []string{warning}})
	}
	assertGeneratedFixtureRows(t, "", rows)
}

func TestGeneratedCiliumAliasRulePresentationContract(t *testing.T) {
	snapshot := generatedFixtureSnapshot(t, "")
	evaluator := netpol.NewEvaluator()
	result, err := evaluator.EvaluateSubject(netpol.SubjectRef{
		Kind: netpol.SubjectPod, Namespace: fixtureSource, Name: "cnp-observe",
	}, snapshot, netpol.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []struct {
		spec        string
		ordinal     int
		index       int
		action      netpol.PolicyAction
		matches     int
		state       netpol.AccessState
		ports       string
		peer, other bool
	}{
		{"spec", 0, 0, netpol.PolicyActionAllow, 0, netpol.AccessDisallowed, "", false, false},
		{"spec", 0, 1, netpol.PolicyActionAllow, 1, netpol.AccessAllowed, "TCP/8080", true, true},
		{"specs[0]", 1, 0, netpol.PolicyActionDeny, 1, netpol.AccessDisallowed, "", true, false},
	} {
		t.Run(fmt.Sprintf("%s/%s/%d", expected.spec, expected.action, expected.index), func(t *testing.T) {
			for index := range result.Egress.Rules {
				rule := &result.Egress.Rules[index]
				if rule.ID.SourceType() != netpol.PolicyTypeCiliumNetworkPolicy ||
					rule.ID.PolicyName != "cnp-observe" || rule.ID.PolicySpecIndex != expected.ordinal ||
					rule.ID.Index != expected.index || rule.ID.Action != expected.action {
					continue
				}
				if rule.PolicySpec != expected.spec || rule.SubjectPodCount != 1 ||
					rule.SubjectMatchCount != expected.matches || len(rule.Warnings) != 0 {
					t.Fatalf("wrong rule visibility/provenance metadata: %+v", rule)
				}
				rows := evaluator.RuleApplicability(result, netpol.Egress, rule.ID, sets.New(netpol.PrimitivePod))
				for rowIndex := range rows {
					row := &rows[rowIndex]
					if row.Primitive.Ref.Namespace != fixtureOther || row.Primitive.Ref.Name != "control" {
						continue
					}
					var ports []string
					for _, permission := range row.Permissions {
						ports = append(ports, permission.String())
					}
					if row.EffectiveState != expected.state || row.PeerMatches != expected.peer ||
						row.OppositeSideAllows != expected.other || strings.Join(ports, ", ") != expected.ports {
						t.Fatalf("wrong underlying rule applicability: %+v", row)
					}
					return
				}
				t.Fatal("control applicability row missing")
				return
			}
			t.Fatal("combined-spec rule missing from evaluator results")
		})
	}
}

func TestGeneratedCiliumProbeSemantics(t *testing.T) {
	origin := "CiliumNetworkPolicy " + fixtureSource + "/probe-cilium-features-fixture-run: egress allow rule "
	warnings := []string{
		origin + "0: fromRequires/toRequires identity constraints are not supported",
		origin + "1: cloud-provider groups require runtime Cilium resolution",
		origin + "2: CIDR group references require runtime Cilium resolution",
		origin + `3: peer selector cannot be evaluated: Cilium identity selector "io.cilium.k8s.policy.unmodeled" is not supported`,
		origin + "4: Cilium TLS, SNI, and listener constraints cannot be evaluated from the policy snapshot",
	}
	control := fixtureRowContract{"control", "cnp-client", fixtureSource, "cnp-server", fixtureTarget, netpol.Egress, netpol.AccessAllowed, "TCP/8081", true, true, nil}
	assertGeneratedFixtureRows(t, "cilium-features", []fixtureRowContract{
		{"matched", "uncertain-client", fixtureSource, "control", fixtureOther, netpol.Egress, netpol.AccessPartialData, "TCP/443", true, true, warnings},
		{"unmodeled", "uncertain-client", fixtureSource, "cnp-server", fixtureTarget, netpol.Egress, netpol.AccessPartialData, "no ports", false, false, nil},
		control,
	})
	warning := `CiliumNetworkPolicy ` + fixtureSource + `/probe-cilium-rejected-fixture-run spec: Cilium rejects this policy: specs[0]: egress allow rule 0: unable to parse port "70000": strconv.ParseUint: parsing "70000": value out of range`
	assertGeneratedFixtureRows(t, "cilium-rejected", []fixtureRowContract{
		{"rejected", "uncertain-client", fixtureSource, "control", fixtureOther, netpol.Egress, netpol.AccessPartialData, "SCTP/all, TCP/all, UDP/all", true, true, []string{warning}},
		control,
	})
}

func TestGeneratedIstioProbeSemantics(t *testing.T) {
	var rows []fixtureRowContract
	for _, class := range []string{"l7", "request"} {
		for _, action := range []string{"allow", "deny"} {
			name := class + "-" + action
			origin := "AuthorizationPolicy " + fixtureTarget + "/probe-istio-" + name + "-fixture-run: ingress " + action + " rule "
			warnings := []string{origin + "0: Istio L7 operation constraints cannot be evaluated from the policy snapshot"}
			ports, controlPorts := fixtureFull, fixtureFull
			if class == "request" {
				warnings = []string{origin + "0: requestPrincipals depend on JWT request identity", origin + "1: remoteIpBlocks depend on proxy forwarding configuration"}
			} else if action == "deny" {
				warnings = append(warnings, origin+"0: DENY has unmodeled L7 predicates; its ports are not subtracted")
			}
			if action == "allow" {
				ports, controlPorts = fixtureNonTCP, fixtureNonTCP
				if class == "l7" {
					ports = "SCTP/9000, TCP/8080, UDP/5353"
				}
			}
			rows = append(rows,
				fixtureRowContract{name, "authz-" + name, fixtureTarget, "authz-client", fixtureSource, netpol.Ingress, netpol.AccessPartialData, ports, true, true, warnings},
				fixtureRowContract{name + "-control", "authz-" + name, fixtureTarget, "control", fixtureOther, netpol.Ingress, netpol.AccessAllowed, controlPorts, true, true, nil})
		}
	}
	assertGeneratedFixtureRows(t, "istio-features", rows)
	assertGeneratedFixtureRows(t, "istio-custom", []fixtureRowContract{
		{"custom", "authz-default", fixtureTarget, "authz-client", fixtureSource, netpol.Ingress, netpol.AccessPartialData, fixtureFull, true, true,
			[]string{"AuthorizationPolicy " + fixtureTarget + "/probe-istio-custom-fixture-run: ingress custom rule 0: CUSTOM authorization depends on an external provider"}},
		{"custom-control", "authz-default", fixtureTarget, "control", fixtureOther, netpol.Ingress, netpol.AccessAllowed, fixtureFull, true, true, nil},
	})
	assertGeneratedFixtureRows(t, "istio-targetrefs", []fixtureRowContract{
		{"targetrefs", "authz-default", fixtureTarget, "authz-client", fixtureSource, netpol.Ingress, netpol.AccessPartialData, fixtureFull, true, true,
			[]string{"AuthorizationPolicy " + fixtureTarget + "/probe-istio-targetrefs-fixture-run: targetRefs cannot be resolved to pods from the policy snapshot; the pods it selects cannot be determined"}},
		{"targetrefs-control", "authz-inject-optout", fixtureOther, "control", fixtureOther, netpol.Ingress, netpol.AccessAllowed, "TCP/8080", true, true, nil},
	})
	assertGeneratedFixtureRows(t, "istio-root", []fixtureRowContract{
		{"root", "authz-identity", fixtureTarget, "authz-client", fixtureSource, netpol.Ingress, netpol.AccessAllowed, "SCTP/9000, TCP/8080, UDP/5353", true, true, nil},
		{"root-control", "authz-default", fixtureTarget, "authz-client", fixtureSource, netpol.Ingress, netpol.AccessAllowed, fixtureFull, true, true, nil},
	})
}
