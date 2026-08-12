package view

import (
	"errors"
	"testing"

	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/config"
	"github.com/derailed/k9s/internal/dao"
	"github.com/derailed/k9s/internal/view/cmd"
	"github.com/derailed/k9s/internal/watch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
)

func Test_viewMetaFor(t *testing.T) {
	uu := map[string]struct {
		cmd string
		gvr *client.GVR
		p   *cmd.Interpreter
		err error
	}{
		"empty": {
			cmd: "",
			gvr: client.PodGVR,
			err: errors.New("`` command not found"),
		},

		"toast": {
			cmd: "v1/pd",
			gvr: client.PodGVR,
			err: errors.New("`v1/pd` command not found"),
		},

		"gvr": {
			cmd: "v1/pods",
			gvr: client.PodGVR,
			p:   cmd.NewInterpreter("v1/pods"),
			err: errors.New("blah"),
		},

		"short-name": {
			cmd: "po",
			gvr: client.PodGVR,
			p:   cmd.NewInterpreter("v1/pods", "po"),
			err: errors.New("blee"),
		},

		"custom-alias": {
			cmd: "pdl",
			gvr: client.PodGVR,
			p:   cmd.NewInterpreter("v1/pods @fred 'app=blee' default", "pdl"),
			err: errors.New("blee"),
		},

		"inception": {
			cmd: "pdal blee",
			gvr: client.PodGVR,
			p:   cmd.NewInterpreter("v1/pods @fred 'app=blee' blee", "pdal", "pod"),
			err: errors.New("blee"),
		},
	}

	c := &Command{
		alias: &dao.Alias{
			Aliases: config.NewAliases(),
		},
	}
	c.alias.Define(client.PodGVR, "po", "pod", "pods", client.PodGVR.String())
	c.alias.Define(client.NewGVR("pod default"), "pd")
	c.alias.Define(client.NewGVR("pod @fred 'app=blee' default"), "pdl")
	c.alias.Define(client.NewGVR("pdl"), "pdal")

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			p := cmd.NewInterpreter(u.cmd)
			gvr, _, acmd, err := c.viewMetaFor(p)
			if err != nil {
				assert.Equal(t, u.err.Error(), err.Error())
			} else {
				assert.Equal(t, u.gvr, gvr)
				assert.Equal(t, u.p, acmd)
			}
		})
	}
}

func TestResolveNetworkPolicyGraphArgsDefaults(t *testing.T) {
	factory := &networkPolicyGraphTestFactory{
		items: map[string][]runtime.Object{
			client.NsGVR.String() + "|" + client.ClusterScope: {
				npgObject("zeta"),
				npgObject("alpha"),
			},
			client.PodGVR.String() + "|payments": {
				npgObject("web"),
				npgObject("api"),
			},
			client.DpGVR.String() + "|payments": {
				npgObject("worker"),
				npgObject("api"),
			},
			client.JobGVR.String() + "|payments": {
				npgObject("z-cleanup"),
				npgObject("a-cleanup"),
			},
		},
	}

	tests := map[string]struct {
		args     cmd.NetworkPolicyGraphArgs
		expected cmd.NetworkPolicyGraphArgs
	}{
		"bare defaults to first namespace": {
			expected: cmd.NetworkPolicyGraphArgs{Kind: "namespace", Name: "alpha"},
		},
		"pod kind defaults in active namespace": {
			args:     cmd.NetworkPolicyGraphArgs{Kind: "pod"},
			expected: cmd.NetworkPolicyGraphArgs{Kind: "pod", Name: "api", Namespace: "payments"},
		},
		"deployment kind defaults in active namespace": {
			args:     cmd.NetworkPolicyGraphArgs{Kind: "deployment"},
			expected: cmd.NetworkPolicyGraphArgs{Kind: "deployment", Name: "api", Namespace: "payments"},
		},
		"job kind defaults in active namespace": {
			args:     cmd.NetworkPolicyGraphArgs{Kind: "job"},
			expected: cmd.NetworkPolicyGraphArgs{Kind: "job", Name: "a-cleanup", Namespace: "payments"},
		},
		"namespace kind defaults cluster-wide": {
			args:     cmd.NetworkPolicyGraphArgs{Kind: "namespace"},
			expected: cmd.NetworkPolicyGraphArgs{Kind: "namespace", Name: "alpha"},
		},
		"explicit subject does not list": {
			args:     cmd.NetworkPolicyGraphArgs{Kind: "pod", Name: "api", Namespace: "default"},
			expected: cmd.NetworkPolicyGraphArgs{Kind: "pod", Name: "api", Namespace: "default"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			factory.calls = nil
			got, err := resolveNetworkPolicyGraphArgs(factory, test.args, "payments")
			require.NoError(t, err)
			assert.Equal(t, test.expected, got)
			if test.args.Name == "" {
				require.Len(t, factory.calls, 1)
				assert.True(t, factory.calls[0].wait)
			} else {
				assert.Empty(t, factory.calls)
			}
		})
	}
}

func TestResolveNetworkPolicyGraphArgsErrors(t *testing.T) {
	tests := map[string]struct {
		args     cmd.NetworkPolicyGraphArgs
		activeNS string
		items    map[string][]runtime.Object
		err      string
	}{
		"no namespaces": {
			err: "no namespaces found",
		},
		"no pods in active namespace": {
			args:     cmd.NetworkPolicyGraphArgs{Kind: "pod"},
			activeNS: "payments",
			err:      "no pods found in namespace payments",
		},
		"all namespaces active namespace": {
			args:     cmd.NetworkPolicyGraphArgs{Kind: "deployment"},
			activeNS: client.NamespaceAll,
			err:      "a concrete namespace is required",
		},
		"unknown kind": {
			args: cmd.NetworkPolicyGraphArgs{Kind: "service", Name: "api"},
			err:  "unsupported",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			factory := &networkPolicyGraphTestFactory{items: test.items}
			_, err := resolveNetworkPolicyGraphArgs(factory, test.args, test.activeNS)
			require.ErrorContains(t, err, test.err)
		})
	}
}

type networkPolicyGraphTestFactory struct {
	items map[string][]runtime.Object
	calls []networkPolicyGraphListCall
}

type networkPolicyGraphListCall struct {
	gvr  *client.GVR
	ns   string
	wait bool
}

func (networkPolicyGraphTestFactory) Client() client.Connection { return nil }

func (networkPolicyGraphTestFactory) Get(*client.GVR, string, bool, labels.Selector) (runtime.Object, error) {
	return nil, errors.New("not found")
}

func (f *networkPolicyGraphTestFactory) List(gvr *client.GVR, ns string, wait bool, _ labels.Selector) ([]runtime.Object, error) {
	f.calls = append(f.calls, networkPolicyGraphListCall{gvr: gvr, ns: ns, wait: wait})
	return f.items[gvr.String()+"|"+ns], nil
}

func (networkPolicyGraphTestFactory) ForResource(string, *client.GVR) (informers.GenericInformer, error) {
	return nil, nil
}

func (networkPolicyGraphTestFactory) CanForResource(string, *client.GVR, []string) (informers.GenericInformer, error) {
	return nil, nil
}

func (networkPolicyGraphTestFactory) WaitForCacheSync()      {}
func (networkPolicyGraphTestFactory) DeleteForwarder(string) {}
func (networkPolicyGraphTestFactory) Forwarders() watch.Forwarders {
	return nil
}

func npgObject(name string) runtime.Object {
	return &unstructured.Unstructured{Object: map[string]any{"metadata": map[string]any{"name": name}}}
}
