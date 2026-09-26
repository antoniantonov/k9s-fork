// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"strings"
	"sync"

	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// normalizationCache keeps normalized policies across evaluations. Entries are
// keyed by UID and resourceVersion, so an edited policy is normalized again,
// and entries not seen in the latest snapshot are evicted.
type normalizationCache struct {
	mu      sync.Mutex
	epoch   uint64
	entries map[string]*normalizationEntry
}

type normalizationEntry struct {
	policies []*normalizedPolicy
	epoch    uint64
}

func newNormalizationCache() *normalizationCache {
	return &normalizationCache{entries: make(map[string]*normalizationEntry)}
}

// begin starts a snapshot generation.
func (c *normalizationCache) begin() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.epoch++
	c.mu.Unlock()
}

// sweep evicts entries which the current generation did not use.
func (c *normalizationCache) sweep() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if entry.epoch != c.epoch {
			delete(c.entries, key)
		}
	}
}

// load returns the cached normalization for key or computes it. Normalized
// policies are never mutated after finalize, so evaluations may share them.
func (c *normalizationCache) load(key string, normalize func() []*normalizedPolicy) []*normalizedPolicy {
	if c == nil || key == "" {
		return normalize()
	}
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		entry.epoch = c.epoch
		c.mu.Unlock()
		return entry.policies
	}
	c.mu.Unlock()
	policies := normalize()
	c.mu.Lock()
	c.entries[key] = &normalizationEntry{policies: policies, epoch: c.epoch}
	c.mu.Unlock()
	return policies
}

func (c *normalizationCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func nativeCacheKey(policy *netv1.NetworkPolicy) string {
	if policy.UID == "" || policy.ResourceVersion == "" {
		return ""
	}
	return strings.Join([]string{string(PolicyTypeNetworkPolicy), string(policy.UID), policy.ResourceVersion}, "\x00")
}

func customCacheKey(object *unstructured.Unstructured, policyType PolicyType, istio *istioRootConfig) string {
	uid, version := string(object.GetUID()), object.GetResourceVersion()
	if uid == "" || version == "" {
		return ""
	}
	parts := []string{string(policyType), uid, version, object.GetAPIVersion()}
	if policyType == PolicyTypeIstioAuthorizationPolicy {
		// The root namespace decides whether a policy is mesh-wide.
		parts = append(parts, istio.effectiveRoot(), strings.Join(istio.candidates, ","))
	}
	return strings.Join(parts, "\x00")
}
