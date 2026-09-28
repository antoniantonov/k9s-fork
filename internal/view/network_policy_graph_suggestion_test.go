// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package view

import (
	"sync"
	"testing"

	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/dao"
	"github.com/derailed/k9s/internal/model"
	"github.com/derailed/k9s/internal/watch"
	"github.com/stretchr/testify/assert"
)

func TestNetworkPolicyGraphSuggestionsDuringAliasReload(t *testing.T) {
	aliases := dao.NewAlias(nil)
	app := &App{command: &Command{alias: aliases}, cmdHistory: model.NewHistory(model.MaxHistory)}
	suggest := app.suggestCommand()
	app.factory = watch.NewFactory(&netPolSuggestionConnection{})
	graph := client.NewGVR("netpolgraph")
	aliases.Define(graph, "npg", "npgraph", "netpolgraph")
	aliases.Define(client.NpGVR, "np", "networkpolicies")
	assert.Equal(t, []string{"g", "graph"}, []string(suggest("np")))

	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Go(func() {
		<-start
		for range 1000 {
			aliases.Clear()
			aliases.Define(graph, "npg", "npgraph", "netpolgraph")
			aliases.Define(client.NpGVR, "np", "networkpolicies")
		}
	})
	close(start)
	for range 1000 {
		assert.Subset(t, []string{"g", "graph"}, []string(suggest("np")))
	}
	workers.Wait()

	assert.Equal(t, []string{"g", "graph"}, []string(suggest("np")))
	aliases.Define(graph, "npg-new")
	assert.Equal(t, []string{"g", "g-new", "graph"}, []string(suggest("np")),
		"the callback must see aliases added after it was created")
}

type netPolSuggestionConnection struct {
	client.Connection
}

func (*netPolSuggestionConnection) ValidNamespaceNames() (client.NamespaceNames, error) {
	return nil, nil
}
