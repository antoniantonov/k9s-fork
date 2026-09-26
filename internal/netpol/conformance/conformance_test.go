// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

//go:build conformance

package conformance

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/derailed/k9s/internal/netpol"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type probe struct {
	sourceNamespace, source           string
	destinationNamespace, destination string
	port                              int32
	result                            string
}

// TestLiveConformance evaluates every probed pair with the graph. Definitive
// verdicts must agree with the probe; Partial Data and Unknown verdicts are
// reported but not compared, because the graph declined to decide them.
func TestLiveConformance(t *testing.T) {
	path := os.Getenv("NETPOL_CONFORMANCE_RESULTS")
	if path == "" {
		t.Skip("NETPOL_CONFORMANCE_RESULTS is not set; run scripts/netpol-conformance.sh")
	}
	probes := readProbes(t, path)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	snapshot := loadSnapshot(ctx, t)
	evaluator := netpol.NewEvaluator()
	decided := 0
	for _, item := range probes {
		result, err := evaluator.EvaluateSubject(netpol.SubjectRef{
			Kind: netpol.SubjectPod, Namespace: item.sourceNamespace, Name: item.source,
		}, snapshot, netpol.Options{})
		if err != nil {
			t.Fatalf("evaluate %s/%s: %v", item.sourceNamespace, item.source, err)
		}
		verdict, detail := graphVerdict(&result, &item)
		label := item.sourceNamespace + "/" + item.source + " -> " + item.destinationNamespace + "/" +
			item.destination + ":" + strconv.Itoa(int(item.port))
		if verdict == "" {
			t.Logf("UNDECIDED %s: probe %s, graph %s", label, item.result, detail)
			continue
		}
		decided++
		if verdict != item.result {
			t.Errorf("MISMATCH %s: probe %s, graph %s (%s)", label, item.result, verdict, detail)
			continue
		}
		t.Logf("MATCH %s: %s (%s)", label, verdict, detail)
	}
	if decided == 0 {
		t.Fatal("the graph did not decide any probed pair")
	}
}

func graphVerdict(result *netpol.SubjectResult, item *probe) (verdict, detail string) {
	for _, primitive := range result.Egress.Primitives[netpol.PrimitivePod] {
		if primitive.Ref.Namespace != item.destinationNamespace || primitive.Ref.Name != item.destination {
			continue
		}
		if len(primitive.PairDecisions) != 1 {
			return "", "no single pair decision"
		}
		decision := primitive.PairDecisions[0].Decision
		detail = decision.State.String() + " " + permissionText(decision.Permissions)
		switch decision.State {
		case netpol.AccessPartialData, netpol.AccessUnknown:
			return "", detail
		}
		for _, permission := range decision.Permissions {
			if allowsTCPPort(permission, item.port) {
				return "allowed", detail
			}
		}
		return "denied", detail
	}
	return "", "destination primitive not found"
}

func allowsTCPPort(permission netpol.PortPermission, port int32) bool {
	if permission.Unknown || (permission.Protocol != "" && permission.Protocol != corev1.ProtocolTCP) {
		return false
	}
	if permission.All || permission.Port == nil {
		return true
	}
	start := permission.Port.IntVal
	end := start
	if permission.EndPort != nil {
		end = *permission.EndPort
	}
	return start <= port && port <= end
}

func permissionText(permissions []netpol.PortPermission) string {
	values := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		values = append(values, permission.String())
	}
	if len(values) == 0 {
		return "no ports"
	}
	return strings.Join(values, ", ")
}

func readProbes(t *testing.T, path string) []probe {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open probe results: %v", err)
	}
	defer file.Close()
	var probes []probe
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 6 {
			t.Fatalf("invalid probe line %q", scanner.Text())
		}
		port, err := strconv.ParseInt(fields[4], 10, 32)
		if err != nil {
			t.Fatalf("invalid probe port in %q: %v", scanner.Text(), err)
		}
		probes = append(probes, probe{
			sourceNamespace: fields[0], source: fields[1],
			destinationNamespace: fields[2], destination: fields[3],
			port: int32(port), result: fields[5],
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read probe results: %v", err)
	}
	return probes
}

// loadSnapshot lists the same resources the k9s model uses.
func loadSnapshot(ctx context.Context, t *testing.T) netpol.Snapshot {
	t.Helper()
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		t.Fatalf("load kubeconfig: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("create clientset: %v", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatalf("create dynamic client: %v", err)
	}
	all := metav1.ListOptions{}
	snapshot := netpol.Snapshot{IstioRootNamespace: netpol.DefaultIstioRootNamespace, GeneratedAt: time.Now()}
	pods, err := clientset.CoreV1().Pods("").List(ctx, all)
	if err != nil {
		t.Fatalf("list pods: %v", err)
	}
	snapshot.Pods = pods.Items
	namespaces, err := clientset.CoreV1().Namespaces().List(ctx, all)
	if err != nil {
		t.Fatalf("list namespaces: %v", err)
	}
	snapshot.Namespaces = namespaces.Items
	policies, err := clientset.NetworkingV1().NetworkPolicies("").List(ctx, all)
	if err != nil {
		t.Fatalf("list network policies: %v", err)
	}
	snapshot.NetworkPolicies = policies.Items
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, all)
	if err != nil {
		t.Fatalf("list deployments: %v", err)
	}
	snapshot.Deployments = deployments.Items
	replicaSets, err := clientset.AppsV1().ReplicaSets("").List(ctx, all)
	if err != nil {
		t.Fatalf("list replica sets: %v", err)
	}
	snapshot.ReplicaSets = replicaSets.Items
	custom := func(group, version, resource string) []unstructured.Unstructured {
		list, err := dynamicClient.Resource(schema.GroupVersionResource{Group: group, Version: version, Resource: resource}).
			List(ctx, all)
		if err != nil {
			t.Fatalf("list %s.%s: %v", resource, group, err)
		}
		return list.Items
	}
	snapshot.CiliumNetworkPolicies = custom("cilium.io", "v2", "ciliumnetworkpolicies")
	snapshot.CiliumClusterwideNetworkPolicies = custom("cilium.io", "v2", "ciliumclusterwidenetworkpolicies")
	snapshot.IstioAuthorizationPolicies = custom("security.istio.io", "v1", "authorizationpolicies")
	return snapshot
}
