// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_newStyle(t *testing.T) {
	s := newStyle()

	assert.Equal(t, Color("black"), s.Body.BgColor)
	assert.Equal(t, Color("cadetblue"), s.Body.FgColor)
	assert.Equal(t, Color("lightskyblue"), s.Frame.Status.NewColor)
	assert.Equal(t, Color("darkgreen"), s.Views.Reachability.AllowedColor)
	assert.Equal(t, Color("darkred"), s.Views.Reachability.DisallowedColor)
	assert.Equal(t, Color("darkorange"), s.Views.Reachability.PartialDataColor)
}
