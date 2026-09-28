// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package view

import (
	"strings"
	"testing"

	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/dao"
	"github.com/derailed/k9s/internal/netpol"
	"github.com/derailed/k9s/internal/ui"
	"github.com/derailed/k9s/internal/view/cmd"
	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestNetworkPolicyGraphRejectedSiblingDiagnosticsStayPairScoped(t *testing.T) {
	const reason = `Cilium rejects this policy: specs[0]: egress allow rule 0: unable to parse port "70000": strconv.ParseUint: parsing "70000": value out of range`
	const warning = "CiliumNetworkPolicy payments/rejected-sibling spec: " + reason
	view := newTestNetworkPolicyGraph()
	result := testSubjectResult()
	result.Warnings = []string{warning}
	port443, port8080 := intstr.FromInt32(443), intstr.FromInt32(8080)
	result.Egress.Rules = []netpol.RuleResult{{
		ID: netpol.RuleID{
			PolicyNamespace: "payments", PolicyName: "rejected-sibling",
			PolicyType: netpol.PolicyTypeCiliumNetworkPolicy, PolicyVersion: "cilium.io/v2",
			Direction: netpol.Egress, Action: netpol.PolicyActionAllow,
		},
		PolicySpec: "spec", PolicySpecCount: 2, SubjectPodCount: 1, SubjectMatchCount: 1,
		Permissions: []netpol.PortPermission{{Protocol: corev1.ProtocolTCP, Port: &port443}},
		Warnings:    []string{reason},
	}}
	result.Egress.Primitives = map[netpol.PrimitiveKind][]netpol.PrimitiveResult{
		netpol.PrimitivePod: {
			{
				Ref:   netpol.PrimitiveRef{Kind: netpol.PrimitivePod, Namespace: "payments", Name: "affected"},
				State: netpol.AccessPartialData, TotalPairs: 1,
				Permissions: []netpol.PortPermission{
					{Protocol: corev1.ProtocolSCTP, All: true},
					{Protocol: corev1.ProtocolTCP, All: true},
					{Protocol: corev1.ProtocolUDP, All: true},
				},
				Warnings: []string{warning},
			},
		},
	}
	view.kinds = sets.New(netpol.PrimitivePod)
	view.applyResult(result)
	view.focusDirection(netpol.Egress)
	selectRule(t, view, result, netpol.Egress, 0)
	detail := view.detailItem.(*ui.RuleDetails)
	ruleText := renderNetPolDetailText(t, detail.Text)
	assert.Contains(t, ruleText, "Policy type: CiliumNetworkPolicy\nPolicy API version: cilium.io/v2")
	assert.Contains(t, ruleText, "Action: allow\nRule index: 0 in spec (spec index 0)\nState: Partial Data (Partial Data)")
	assert.Contains(t, ruleText, "Ports: TCP/443")
	assert.Contains(t, ruleText, "Warnings:\n  - "+reason)
	assert.Equal(t, "payments/rejected-sibling spec #0", view.panels[netpol.Egress].GetCell(0, 0).Text)

	// An unselected subject can reach a clean control while another peer is
	// selected by the rejected policy, so its global warning must remain.
	result.Subject.Ref.Name = "unselected"
	result.Subject.Pods[0].Name = "unselected"
	result.Egress.Rules = nil
	result.Egress.Primitives[netpol.PrimitivePod] = append(result.Egress.Primitives[netpol.PrimitivePod], netpol.PrimitiveResult{
		Ref:   netpol.PrimitiveRef{Kind: netpol.PrimitivePod, Namespace: "payments", Name: "control"},
		State: netpol.AccessAllowed, AllowedPairs: 1, TotalPairs: 1,
		Permissions: []netpol.PortPermission{{Protocol: corev1.ProtocolTCP, Port: &port8080}},
	})
	view.applySubject(result.Subject.Ref)
	view.applyResult(result)
	view.focusDirection(netpol.Egress)
	detail = view.detailItem.(*ui.RuleDetails)
	require.Equal(t, 3, detail.Applicability.GetRowCount())
	for row, expected := range []struct {
		name, state, ports string
	}{
		{"affected", "Partial Data", "SCTP/all, TCP/all, UDP/all"},
		{"control", "Allowed", "TCP/8080"},
	} {
		assert.Equal(t, "Pod payments/"+expected.name, detail.Applicability.GetCell(row+1, 0).Text)
		assert.Equal(t, expected.state, detail.Applicability.GetCell(row+1, 3).Text)
		assert.Equal(t, expected.ports, detail.Applicability.GetCell(row+1, 4).Text)
	}
	assert.Contains(t, renderNetPolDetailText(t, detail.Text), "Warning: "+warning)

	view.switchMode()
	for index, expected := range []struct {
		state, ports string
		warned       bool
	}{
		{"Partial Data", "SCTP/all, TCP/all, UDP/all", true},
		{"Allowed", "TCP/8080", false},
	} {
		selectPrimitive(t, view, result, netpol.Egress, netpol.PrimitivePod, index)
		text := renderNetPolDetailText(t, view.detailItem.(*tview.TextView))
		assert.Contains(t, text, "\nState: "+expected.state+"\n")
		assert.Contains(t, text, "\nPorts: "+expected.ports+"\n")
		assert.Equal(t, expected.warned, strings.Contains(text, "\nWarnings:\n"))
		assert.Contains(t, text, "\nWarning: "+warning, "global diagnostics remain visible without degrading the control")
		assert.Contains(t, view.subjectInfo.SummaryText(), "PARTIAL DATA (1 warning(s))")
	}
}

func renderNetPolDetailText(t *testing.T, text *tview.TextView) string {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	require.NoError(t, screen.Init())
	t.Cleanup(screen.Fini)
	screen.SetSize(512, 64)
	text.SetRect(0, 0, 512, 64)
	text.Draw(screen)
	x, y, width, height := text.GetInnerRect()
	lines := make([]string, 0, height)
	for row := y; row < y+height; row++ {
		var line strings.Builder
		for column := x; column < x+width; column++ {
			r, _, _, _ := screen.GetContent(column, row)
			line.WriteRune(r)
		}
		lines = append(lines, strings.TrimRight(line.String(), " "))
	}
	return strings.Join(lines, "\n")
}

func TestNetworkPolicyGraphUnavailablePolicyNavigationDoesNotUseForeignAlias(t *testing.T) {
	for _, test := range []struct {
		policyType netpol.PolicyType
		gvr        *client.GVR
	}{
		{netpol.PolicyTypeCiliumNetworkPolicy, client.CnpGVR},
		{netpol.PolicyTypeCiliumClusterwideNetworkPolicy, client.CcnpGVR},
		{netpol.PolicyTypeIstioAuthorizationPolicy, client.AuthzGVR},
		{netpol.PolicyTypeIstioAuthorizationPolicy, client.AuthzV1BetaGVR},
	} {
		t.Run(test.gvr.String(), func(t *testing.T) {
			view := newTestNetworkPolicyGraph()
			result := testSubjectResult()
			rule := &result.Ingress.Rules[0]
			rule.ID.PolicyType, rule.ID.PolicyVersion = test.policyType, test.gvr.GV().String()
			view.applyResult(result)
			view.focusDirection(netpol.Ingress)
			selectRule(t, view, result, netpol.Ingress, 0)
			command, path, err := view.openPrimitiveTarget()
			require.NoError(t, err)

			router := &Command{alias: dao.NewAlias(nil)}
			foreign := client.NewGVR("policies.example.org/v1/" + test.gvr.R())
			router.alias.Define(foreign, foreign.R(), foreign.R()+"."+foreign.G())
			gvr, _, _, err := router.viewMetaFor(cmd.NewInterpreter(command))
			require.ErrorContains(t, err, "`"+test.gvr.R()+"."+test.gvr.G()+"` command not found")
			assert.Equal(t, client.NoGVR, gvr)

			router.alias = nil
			_, _, _, err = router.viewMetaFor(cmd.NewInterpreter(command))
			require.EqualError(t, err, "no connection available")
			yamlGVR, resourcePath, found := view.yamlTarget()
			require.True(t, found)
			assert.Equal(t, test.gvr, yamlGVR, "YAML retains the evaluated served version even after discovery disappears")
			assert.Equal(t, path, resourcePath)
		})
	}
}
