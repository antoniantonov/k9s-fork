// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// evidenceKey identifies one piece of evidence. It starts with the rule ID
// followed by a NUL byte, which rule IDs never contain.
func evidenceKey(evidence *PolicyEvidence) string {
	var b strings.Builder
	b.WriteString(evidence.RuleID.String())
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(evidence.PeerIndex))
	b.WriteByte(0)
	b.WriteString(permissionsKey(evidence.Ports))
	return b.String()
}

func ruleKeyOf(evidenceKey string) string {
	if index := strings.IndexByte(evidenceKey, 0); index >= 0 {
		return evidenceKey[:index]
	}
	return evidenceKey
}

// uniqueEvidenceKeys deduplicates evidence and returns it sorted by key,
// together with the keys so callers can merge without recomputing them.
func uniqueEvidenceKeys(in []PolicyEvidence) (out []PolicyEvidence, keys []string) {
	if len(in) == 0 {
		return nil, nil
	}
	seen := make(map[string]int, len(in))
	keys = make([]string, 0, len(in))
	for index := range in {
		k := evidenceKey(&in[index])
		if _, ok := seen[k]; !ok {
			keys = append(keys, k)
		}
		seen[k] = index
	}
	slices.Sort(keys)
	out = make([]PolicyEvidence, 0, len(keys))
	for _, k := range keys {
		out = append(out, in[seen[k]])
	}
	return out, keys
}

func uniqueEvidence(in []PolicyEvidence) []PolicyEvidence {
	out, _ := uniqueEvidenceKeys(in)
	return out
}

// evidenceSet merges keyed evidence from many pairs.
type evidenceSet struct {
	items map[string]PolicyEvidence
}

func (s *evidenceSet) add(keys []string, evidence []PolicyEvidence) {
	for index, k := range keys {
		if s.items == nil {
			s.items = make(map[string]PolicyEvidence, len(keys))
		}
		if _, ok := s.items[k]; !ok {
			s.items[k] = evidence[index]
		}
	}
}

func (s *evidenceSet) sorted() []PolicyEvidence {
	if len(s.items) == 0 {
		return nil
	}
	keys := mapsKeys(s.items)
	slices.Sort(keys)
	out := make([]PolicyEvidence, 0, len(keys))
	for _, k := range keys {
		out = append(out, s.items[k])
	}
	return out
}

// ruleAccumulator collects, per rule, the evidence and the subject pods it
// matched while pod and CIDR primitives are evaluated.
type ruleAccumulator struct {
	direction Direction
	items     map[string]*evidenceSet
	subjects  map[string]map[*corev1.Pod]struct{}
}

func newRuleAccumulator(direction Direction) *ruleAccumulator {
	return &ruleAccumulator{
		direction: direction,
		items:     make(map[string]*evidenceSet),
		subjects:  make(map[string]map[*corev1.Pod]struct{}),
	}
}

func (a *ruleAccumulator) add(keys []string, evidence []PolicyEvidence, subject *corev1.Pod) {
	if a == nil {
		return
	}
	for index, k := range keys {
		if evidence[index].RuleID.Direction != a.direction {
			continue
		}
		rule := ruleKeyOf(k)
		set := a.items[rule]
		if set == nil {
			set = &evidenceSet{}
			a.items[rule] = set
		}
		set.add(keys[index:index+1], evidence[index:index+1])
		if a.subjects[rule] == nil {
			a.subjects[rule] = make(map[*corev1.Pod]struct{})
		}
		a.subjects[rule][subject] = struct{}{}
	}
}

func (a *ruleAccumulator) evidence(rule string) []PolicyEvidence {
	if set := a.items[rule]; set != nil {
		return set.sorted()
	}
	return nil
}

func (a *ruleAccumulator) subjectCount(rule string) int {
	return len(a.subjects[rule])
}
