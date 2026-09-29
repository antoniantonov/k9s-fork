// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	DefaultResultLimit        = 5_000
	DefaultIstioRootNamespace = "istio-system"
)

// Synthetic rule kinds explain results that no concrete policy rule produced.
const (
	// SyntheticUnrestricted means no network-layer policy isolates the pod.
	SyntheticUnrestricted = "unrestricted"
	// SyntheticDefaultDeny means a network-layer policy isolates the pod and
	// no allow rule matches the peer.
	SyntheticDefaultDeny = "default-deny"
	// SyntheticAuthorizationDefaultDeny means an Istio ALLOW policy isolates a
	// mesh workload's TCP ingress and no allow rule matches the request.
	SyntheticAuthorizationDefaultDeny = "authorization-default-deny"
)

type Direction uint8

const (
	Ingress Direction = iota
	Egress
)

func (d Direction) String() string {
	if d == Egress {
		return "Egress"
	}
	return "Ingress"
}

// PolicyType identifies the API resource which supplied a policy rule.
type PolicyType string

const (
	PolicyTypeNetworkPolicy                  PolicyType = "np"
	PolicyTypeCiliumNetworkPolicy            PolicyType = "cnp"
	PolicyTypeCiliumClusterwideNetworkPolicy PolicyType = "ccnp"
	PolicyTypeIstioAuthorizationPolicy       PolicyType = "authz"
	PolicyTypeSynthetic                      PolicyType = "synthetic"
)

func (t PolicyType) String() string {
	if t == "" {
		return string(PolicyTypeNetworkPolicy)
	}
	return string(t)
}

// Kind returns the Kubernetes kind represented by the policy type.
func (t PolicyType) Kind() string {
	switch t {
	case PolicyTypeCiliumNetworkPolicy:
		return "CiliumNetworkPolicy"
	case PolicyTypeCiliumClusterwideNetworkPolicy:
		return "CiliumClusterwideNetworkPolicy"
	case PolicyTypeIstioAuthorizationPolicy:
		return "AuthorizationPolicy"
	case PolicyTypeSynthetic:
		return "Synthetic"
	default:
		return "NetworkPolicy"
	}
}

// PolicyAction is the effect of a matching policy rule.
type PolicyAction string

const (
	PolicyActionAllow PolicyAction = "allow"
	PolicyActionDeny  PolicyAction = "deny"
	// PolicyActionCustom delegates the decision to an external authorizer.
	PolicyActionCustom PolicyAction = "custom"
)

func (a PolicyAction) String() string {
	if a == "" {
		return string(PolicyActionAllow)
	}
	return string(a)
}

type SubjectKind uint8

const (
	SubjectPod SubjectKind = iota
	SubjectDeployment
	SubjectJob
	SubjectNamespace
)

func (k SubjectKind) String() string {
	switch k {
	case SubjectDeployment:
		return "Deployment"
	case SubjectJob:
		return "Job"
	case SubjectNamespace:
		return "Namespace"
	default:
		return "Pod"
	}
}

type PrimitiveKind uint8

const (
	PrimitiveCIDR PrimitiveKind = iota
	PrimitivePod
	PrimitiveNamespace
	PrimitiveDeployment
	PrimitiveJob
)

func (k PrimitiveKind) String() string {
	switch k {
	case PrimitivePod:
		return "Pod"
	case PrimitiveNamespace:
		return "Namespace"
	case PrimitiveDeployment:
		return "Deployment"
	case PrimitiveJob:
		return "Job"
	default:
		return "CIDR"
	}
}

func AllPrimitiveKinds() sets.Set[PrimitiveKind] {
	return sets.New(
		PrimitiveCIDR,
		PrimitivePod,
		PrimitiveNamespace,
		PrimitiveDeployment,
		PrimitiveJob,
	)
}

type AccessState uint8

const (
	AccessAllowed AccessState = iota
	AccessDisallowed
	AccessPartial
	AccessUnknown
	AccessPartialData
)

func (s AccessState) String() string {
	switch s {
	case AccessDisallowed:
		return "Disallowed"
	case AccessPartial:
		return "Partial"
	case AccessUnknown:
		return "Unknown"
	case AccessPartialData:
		return "Partial Data"
	default:
		return "Allowed"
	}
}

type SubjectRef struct {
	Kind      SubjectKind
	Namespace string
	Name      string
	UID       types.UID
}

func (r SubjectRef) ID() string {
	return stableID(r.Kind.String(), r.Namespace, r.Name, string(r.UID))
}

type PodRef struct {
	Namespace string
	Name      string
	UID       types.UID
}

func (r PodRef) ID() string {
	return stableID("Pod", r.Namespace, r.Name, string(r.UID))
}

type PrimitiveRef struct {
	Kind       PrimitiveKind
	Namespace  string
	Name       string
	UID        types.UID
	CIDR       string
	CIDRExcept []string
}

//nolint:gocritic // Value receiver preserves the public API and supports composite literals.
func (r PrimitiveRef) ID() string {
	if r.Kind == PrimitiveCIDR {
		excepts := slices.Clone(r.CIDRExcept)
		slices.Sort(excepts)
		return stableID(r.Kind.String(), r.CIDR, strings.Join(excepts, ","))
	}
	return stableID(r.Kind.String(), r.Namespace, r.Name, string(r.UID))
}

type RuleID struct {
	PolicyNamespace string
	PolicyName      string
	PolicyUID       types.UID
	PolicyType      PolicyType
	PolicyVersion   string
	PolicySpecIndex int
	Action          PolicyAction
	Direction       Direction
	Index           int
	SyntheticKind   string
}

func (r RuleID) String() string {
	var b strings.Builder
	b.Grow(len(r.PolicyNamespace) + len(r.PolicyName) + len(r.PolicyUID) + len(r.SyntheticKind) + 48)
	for index, part := range []string{
		r.PolicyNamespace,
		r.PolicyName,
		string(r.PolicyUID),
		r.Direction.String(),
		strconv.Itoa(r.Index),
		r.SyntheticKind,
	} {
		if index > 0 {
			b.WriteByte(stableIDSeparator)
		}
		b.WriteString(part)
	}
	// Preserve native NetworkPolicy IDs while making rules from different CRD
	// kinds, top-level Cilium specs, and actions unambiguous.
	if r.PolicyType != "" && r.PolicyType != PolicyTypeNetworkPolicy {
		for _, part := range []string{
			r.PolicyType.String(),
			r.PolicyVersion,
			strconv.Itoa(r.PolicySpecIndex),
			r.Action.String(),
		} {
			b.WriteByte(stableIDSeparator)
			b.WriteString(part)
		}
	}
	return b.String()
}

// SourceType returns the rule's effective source policy type.
//
//nolint:gocritic // Value receiver preserves the public API and supports composite literals.
func (r RuleID) SourceType() PolicyType {
	if r.SyntheticKind != "" || r.PolicyName == "" {
		return PolicyTypeSynthetic
	}
	if r.PolicyType == "" {
		return PolicyTypeNetworkPolicy
	}
	return r.PolicyType
}

type PortPermission struct {
	Protocol corev1.Protocol
	Port     *intstr.IntOrString
	EndPort  *int32
	All      bool
	Unknown  bool
}

func (p PortPermission) String() string {
	if p.Unknown {
		return "unknown"
	}
	proto := p.Protocol
	if proto == "" {
		proto = corev1.ProtocolTCP
	}
	if p.All || p.Port == nil {
		return string(proto) + "/all"
	}
	value := p.Port.String()
	if p.EndPort != nil {
		value += fmt.Sprintf("-%d", *p.EndPort)
	}
	return string(proto) + "/" + value
}

type PolicyEvidence struct {
	RuleID      RuleID
	PolicyTypes []netv1.PolicyType
	PeerIndex   int
	Ports       []PortPermission
	Summary     string
}

type Decision struct {
	State       AccessState
	Permissions []PortPermission
	Evidence    []PolicyEvidence
	Explanation string
	Warnings    []string
}

type PairDecision struct {
	Source      PodRef
	Destination PodRef
	Decision    Decision
}

type RuleResult struct {
	ID                RuleID
	SubjectPodCount   int
	SubjectMatchCount int
	PolicySelector    string
	// PolicySpec names the Cilium rule entry, such as spec or specs[1].
	PolicySpec string
	// PolicySpecCount is the number of top-level Cilium rule entries in the
	// policy. Rule labels include PolicySpec when it is greater than one.
	PolicySpecCount int
	Peers           []string
	YAML            string
	PeerSummary     string
	Permissions     []PortPermission
	Evidence        []PolicyEvidence
	Synthetic       bool
	Notes           []string
	Warnings        []string
}

//nolint:gocritic // Value receiver preserves the public API.
func (r RuleResult) StableID() string {
	return r.ID.String()
}

type PrimitiveResult struct {
	Ref           PrimitiveRef
	State         AccessState
	AllowedPairs  int
	TotalPairs    int
	Permissions   []PortPermission
	Evidence      []PolicyEvidence
	Explanation   string
	Warnings      []string
	PairDecisions []PairDecision
}

//nolint:gocritic // Value receiver preserves the public API.
func (r PrimitiveResult) StableID() string {
	return r.Ref.ID()
}

type ApplicabilityRow struct {
	Primitive   PrimitiveResult
	PeerMatches bool
	// OppositeSideAllows is true for CIDR rows because opposite-side
	// applicability is not meaningful for an address-only peer.
	OppositeSideAllows bool
	EffectiveState     AccessState
	Permissions        []PortPermission
}

type Subject struct {
	Ref  SubjectRef
	Pods []PodRef
}

type DirectionResult struct {
	Rules      []RuleResult
	Primitives map[PrimitiveKind][]PrimitiveResult
}

func (r DirectionResult) FilteredPrimitives(kinds sets.Set[PrimitiveKind]) []PrimitiveResult {
	var results []PrimitiveResult
	for _, kind := range slices.Sorted(maps.Keys(r.Primitives)) {
		if kinds.Has(kind) {
			results = append(results, r.Primitives[kind]...)
		}
	}
	return results
}

type SubjectResult struct {
	Subject     Subject
	Ingress     DirectionResult
	Egress      DirectionResult
	GeneratedAt time.Time
	// Warnings explain why results for this subject are incomplete.
	Warnings []string
	// Notes describe assumptions and fallbacks which do not make any result
	// incomplete on their own.
	Notes       []string
	Truncated   bool
	ResultLimit int
}

//nolint:gocritic // Value receiver preserves the public API.
func (r SubjectResult) Direction(direction Direction) DirectionResult {
	if direction == Egress {
		return r.Egress
	}
	return r.Ingress
}

type Snapshot struct {
	Pods                             []corev1.Pod
	Namespaces                       []corev1.Namespace
	NetworkPolicies                  []netv1.NetworkPolicy
	CiliumNetworkPolicies            []unstructured.Unstructured
	CiliumClusterwideNetworkPolicies []unstructured.Unstructured
	IstioAuthorizationPolicies       []unstructured.Unstructured
	IstioRootNamespace               string
	// IstioRootNamespaceCandidates lists conflicting root namespaces reported
	// by different Istio revisions. It is empty when the root is unambiguous.
	IstioRootNamespaceCandidates []string
	Deployments                  []appsv1.Deployment
	ReplicaSets                  []appsv1.ReplicaSet
	Jobs                         []batchv1.Job
	Incomplete                   map[string]error
	// Notes carry snapshot-level assumptions, such as configuration fallbacks.
	Notes       []string
	GeneratedAt time.Time
}

type Options struct {
	ResultLimit int
}

func (o Options) Limit() int {
	if o.ResultLimit <= 0 {
		return DefaultResultLimit
	}
	return o.ResultLimit
}

type Evaluator interface {
	EvaluateSubject(SubjectRef, Snapshot, Options) (SubjectResult, error)
	Rules(SubjectResult, Direction) []RuleResult
	Primitives(SubjectResult, Direction, sets.Set[PrimitiveKind]) []PrimitiveResult
	DirectionApplicability(SubjectResult, Direction, sets.Set[PrimitiveKind]) []ApplicabilityRow
	RuleApplicability(SubjectResult, Direction, RuleID, sets.Set[PrimitiveKind]) []ApplicabilityRow
}

const stableIDSeparator = '\x1f'

func stableID(parts ...string) string {
	return strings.Join(parts, string(stableIDSeparator))
}
