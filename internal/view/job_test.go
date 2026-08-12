// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package view

import (
	"testing"

	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJobNetworkPolicyGraphBinding(t *testing.T) {
	j := Job{ResourceViewer: NewBrowser(client.JobGVR)}
	actions := ui.NewKeyActions()
	j.bindKeys(actions)
	action, ok := actions.Get(ui.KeyShiftR)
	require.True(t, ok)
	assert.Equal(t, "Network Reachability", action.Description)
}
