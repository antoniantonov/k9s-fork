// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

// Package conformance compares NetworkPolicy graph verdicts with connection
// probes against a live cluster running real Cilium and Istio. Its test only
// builds with the "conformance" tag and is driven by
// scripts/netpol-conformance.sh.
package conformance
