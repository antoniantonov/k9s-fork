// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package cmd

import (
	"maps"
	"slices"
	"strings"
)

const (
	nsKey      = "ns"
	topicKey   = "topic"
	filterKey  = "filter"
	fuzzyKey   = "fuzzy"
	labelKey   = "labels"
	contextKey = "context"
	kindKey    = "kind"
	nameKey    = "name"
)

type args map[string]string

func newArgs(p *Interpreter, aa []string) args {
	arguments := make(args, len(aa))
	if len(aa) == 0 {
		return arguments
	}
	if p.IsNetworkPolicyGraphCmd() {
		return newNetworkPolicyGraphArgs(aa)
	}

	for i := 0; i < len(aa); i++ {
		a := strings.TrimSpace(aa[i])
		switch {
		case strings.Index(a, fuzzyFlag) == 0:
			if a == fuzzyFlag {
				i++
				if i < len(aa) {
					arguments[fuzzyKey] = strings.ToLower(strings.TrimSpace(aa[i]))
				}
			} else {
				arguments[fuzzyKey] = strings.ToLower(a[2:])
			}

		case strings.Index(a, filterFlag) == 0:
			if p.IsDirCmd() {
				if _, ok := arguments[topicKey]; !ok {
					arguments[topicKey] = a
				}
			} else {
				arguments[filterKey] = strings.ToLower(a[1:])
			}

		case strings.Index(a, contextFlag) == 0:
			arguments[contextKey] = a[1:]

		case isLabelArg(a):
			arguments[labelKey] = strings.ToLower(a)

		default:
			switch {
			case p.IsContextCmd():
				arguments[contextKey] = a

			case p.IsDirCmd():
				if _, ok := arguments[topicKey]; !ok {
					arguments[topicKey] = a
				}

			case p.IsXrayCmd():
				if _, ok := arguments[topicKey]; ok {
					arguments[nsKey] = strings.ToLower(a)
				} else {
					arguments[topicKey] = strings.ToLower(a)
				}

			default:
				arguments[nsKey] = strings.ToLower(a)
			}
		}
	}

	return arguments
}

func newNetworkPolicyGraphArgs(aa []string) args {
	if len(aa) < 2 || len(aa) > 3 {
		return args{}
	}

	kind, ok := normalizeNetworkPolicyGraphKind(aa[0])
	if !ok || strings.TrimSpace(aa[1]) == "" {
		return args{}
	}
	if kind == netpolGraphKindNS && len(aa) != 2 {
		return args{}
	}

	arguments := args{
		kindKey: kind,
		nameKey: strings.ToLower(strings.TrimSpace(aa[1])),
	}
	if len(aa) == 3 {
		namespace := strings.ToLower(strings.TrimSpace(aa[2]))
		if namespace == "" {
			return args{}
		}
		arguments[nsKey] = namespace
	}

	return arguments
}

func normalizeNetworkPolicyGraphKind(kind string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "po", "pod", "pods":
		return netpolGraphKindPod, true
	case "dp", "deploy", "deployment", "deployments":
		return netpolGraphKindDP, true
	case "job", "jobs":
		return netpolGraphKindJob, true
	case "ns", "namespace", "namespaces":
		return netpolGraphKindNS, true
	default:
		return "", false
	}
}

func (a args) String() string {
	ss := make([]string, 0, len(a))
	kk := maps.Keys(a)
	for _, k := range slices.Sorted(kk) {
		v := a[k]
		switch k {
		case labelKey:
			v = "'" + v + "'"
		case filterKey:
			v = filterFlag + v
		case contextKey:
			v = contextFlag + v
		}
		ss = append(ss, v)
	}

	return strings.Join(ss, " ")
}

func (a args) hasFilters() bool {
	_, fok := a[filterKey]
	_, zok := a[fuzzyKey]
	_, lok := a[labelKey]

	return fok || zok || lok
}

func isLabelArg(arg string) bool {
	for _, flag := range labelFlags {
		if strings.Contains(arg, flag) {
			return true
		}
	}

	return false
}
