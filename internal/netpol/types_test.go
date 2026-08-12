// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package netpol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStableIDs(t *testing.T) {
	subject := SubjectRef{Kind: SubjectDeployment, Namespace: "default", Name: "api", UID: "uid-1"}
	require.Equal(t, "Deployment\x1fdefault\x1fapi\x1fuid-1", subject.ID())

	cidr := PrimitiveRef{Kind: PrimitiveCIDR, CIDR: "10.0.0.0/8", CIDRExcept: []string{"10.2.0.0/16", "10.1.0.0/16"}}
	require.Equal(t, "CIDR\x1f10.0.0.0/8\x1f10.1.0.0/16,10.2.0.0/16", cidr.ID())
}

func TestAllPrimitiveKinds(t *testing.T) {
	require.Len(t, AllPrimitiveKinds(), 5)
}
