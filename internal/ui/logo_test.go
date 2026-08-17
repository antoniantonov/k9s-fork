// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package ui_test

import (
	"strings"
	"testing"

	"github.com/derailed/k9s/internal/config"
	"github.com/derailed/k9s/internal/ui"
	"github.com/derailed/tcell/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const logoWidth = 40

type logoCell struct {
	r     rune
	style tcell.Style
}

func renderLogo(t *testing.T, logo *ui.Logo) [][]logoCell {
	t.Helper()

	screen := tcell.NewSimulationScreen("UTF-8")
	require.NoError(t, screen.Init())
	t.Cleanup(screen.Fini)
	screen.SetSize(logoWidth, 7)
	logo.SetRect(0, 0, logoWidth, 7)
	logo.Draw(screen)

	rows := make([][]logoCell, 7)
	for row := range rows {
		rows[row] = make([]logoCell, logoWidth)
		for column := range logoWidth {
			r, _, style, _ := screen.GetContent(column, row)
			rows[row][column] = logoCell{r: r, style: style}
		}
	}
	return rows
}

func rowText(row []logoCell) string {
	var text strings.Builder
	for _, cell := range row {
		text.WriteRune(cell.r)
	}
	return strings.TrimSpace(text.String())
}

func assertRowStyle(t *testing.T, row []logoCell, fg, bg tcell.Color) {
	t.Helper()

	for _, cell := range row {
		if cell.r == ' ' {
			continue
		}
		actualFG, actualBG, _ := cell.style.Decompose()
		assert.Equal(t, fg, actualFG)
		assert.Equal(t, bg, actualBG)
	}
}

func assertRowForeground(t *testing.T, row []logoCell, fg tcell.Color) {
	t.Helper()

	for _, cell := range row {
		if cell.r == ' ' {
			continue
		}
		actualFG, _, _ := cell.style.Decompose()
		assert.Equal(t, fg, actualFG)
	}
}

func TestNewLogoView(t *testing.T) {
	v := ui.NewLogo(config.NewStyles())
	v.Reset()

	const elogo = "[#ffa500::b] ____  __ ________       \n[#ffa500::b]|    |/  /   __   \\______\n[#ffa500::b]|       /\\____    /  ___/\n[#ffa500::b]|    \\   \\  /    /\\___  \\\n[#ffa500::b]|____|\\__ \\/____//____  /\n[#ffa500::b]         \\/           \\/ \n"
	assert.Equal(t, elogo, v.Logo().GetText(false))
	assert.Empty(t, v.Status().GetText(false))
}

func TestLogoStatus(t *testing.T) {
	uu := map[string]struct {
		logo, msg, e string
	}{
		"info": {
			"[#008000::b] ____  __ ________       \n[#008000::b]|    |/  /   __   \\______\n[#008000::b]|       /\\____    /  ___/\n[#008000::b]|    \\   \\  /    /\\___  \\\n[#008000::b]|____|\\__ \\/____//____  /\n[#008000::b]         \\/           \\/ \n",
			"blee",
			"[#ffffff::b]blee\n",
		},
		"warn": {
			"[#c71585::b] ____  __ ________       \n[#c71585::b]|    |/  /   __   \\______\n[#c71585::b]|       /\\____    /  ___/\n[#c71585::b]|    \\   \\  /    /\\___  \\\n[#c71585::b]|____|\\__ \\/____//____  /\n[#c71585::b]         \\/           \\/ \n",
			"blee",
			"[#ffffff::b]blee\n",
		},
		"err": {
			"[#ff0000::b] ____  __ ________       \n[#ff0000::b]|    |/  /   __   \\______\n[#ff0000::b]|       /\\____    /  ___/\n[#ff0000::b]|    \\   \\  /    /\\___  \\\n[#ff0000::b]|____|\\__ \\/____//____  /\n[#ff0000::b]         \\/           \\/ \n",
			"blee",
			"[#ffffff::b]blee\n",
		},
	}

	v := ui.NewLogo(config.NewStyles())
	for n := range uu {
		k, u := n, uu[n]
		t.Run(k, func(t *testing.T) {
			switch k {
			case "info":
				v.Info(u.msg)
			case "warn":
				v.Warn(u.msg)
			case "err":
				v.Err(u.msg)
			}
			assert.Equal(t, u.logo, v.Logo().GetText(false))
			assert.Equal(t, u.e, v.Status().GetText(false))
		})
	}
}

func TestLogoViewBadgeRendersOnStatusRow(t *testing.T) {
	styles := config.NewStyles()
	v := ui.NewLogo(styles)

	token := v.SetViewBadge("read-only graph", tcell.ColorYellow, tcell.ColorRed)

	assert.NotZero(t, token)
	rows := renderLogo(t, v)
	assert.Equal(t, "read-only graph", rowText(rows[6]))
	assertRowStyle(t, rows[6], tcell.ColorYellow, tcell.ColorRed)
	for row := range 6 {
		assertRowForeground(t, rows[row], styles.Body().LogoColor.Color())
	}
}

func TestLogoViewBadgeRestoredAfterTransientStatus(t *testing.T) {
	v := ui.NewLogo(config.NewStyles())
	v.SetViewBadge("read-only graph", tcell.ColorYellow, tcell.ColorRed)

	v.Info("loading")
	rows := renderLogo(t, v)
	assert.Equal(t, "loading", rowText(rows[6]))

	v.Reset()
	rows = renderLogo(t, v)
	assert.Equal(t, "read-only graph", rowText(rows[6]))
	assertRowStyle(t, rows[6], tcell.ColorYellow, tcell.ColorRed)
}

func TestLogoViewBadgeTokenOwnershipAndRepeatedClear(t *testing.T) {
	v := ui.NewLogo(config.NewStyles())
	first := v.SetViewBadge("first", tcell.ColorYellow, tcell.ColorRed)
	second := v.SetViewBadge("second", tcell.ColorYellow, tcell.ColorRed)

	v.ClearViewBadge(0)
	v.ClearViewBadge(first)
	assert.Equal(t, "second", rowText(renderLogo(t, v)[6]))

	v.ClearViewBadge(second)
	v.ClearViewBadge(second)
	assert.Empty(t, rowText(renderLogo(t, v)[6]))

	third := v.SetViewBadge("third", tcell.ColorYellow, tcell.ColorRed)
	v.ClearViewBadge(second)
	assert.Equal(t, "third", rowText(renderLogo(t, v)[6]))
	v.ClearViewBadge(third)
	assert.Empty(t, rowText(renderLogo(t, v)[6]))
}

func TestLogoViewBadgeClearDoesNotClearTransientStatus(t *testing.T) {
	v := ui.NewLogo(config.NewStyles())
	token := v.SetViewBadge("read-only graph", tcell.ColorYellow, tcell.ColorRed)
	v.Warn("working")

	v.ClearViewBadge(token)
	assert.Equal(t, "working", rowText(renderLogo(t, v)[6]))

	v.Reset()
	assert.Empty(t, rowText(renderLogo(t, v)[6]))
}

func TestLogoViewBadgeSurvivesStyleReloadAndTransientLayering(t *testing.T) {
	v := ui.NewLogo(config.NewStyles())
	v.SetViewBadge("read-only graph", tcell.ColorYellow, tcell.ColorRed)
	v.Info("loading")

	reloaded := config.NewStyles()
	reloaded.K9s.Body.LogoColor = config.NewColor("blue")
	reloaded.K9s.Body.LogoColorMsg = config.NewColor("fuchsia")
	reloaded.K9s.Body.LogoColorInfo = config.NewColor("aqua")
	v.StylesChanged(reloaded)

	rows := renderLogo(t, v)
	assert.Equal(t, "loading", rowText(rows[6]))
	assertRowStyle(t, rows[6], reloaded.Body().LogoColorMsg.Color(), reloaded.Body().LogoColorInfo.Color())
	for row := range 6 {
		assertRowForeground(t, rows[row], reloaded.Body().LogoColorInfo.Color())
	}

	v.Reset()
	rows = renderLogo(t, v)
	assert.Equal(t, "read-only graph", rowText(rows[6]))
	assertRowStyle(t, rows[6], tcell.ColorYellow, tcell.ColorRed)
	for row := range 6 {
		assertRowForeground(t, rows[row], reloaded.Body().LogoColor.Color())
	}
}

func TestLogoViewBadgeHeadlessSafety(t *testing.T) {
	var logo ui.Logo
	token := logo.SetViewBadge("read-only graph", tcell.ColorYellow, tcell.ColorRed)
	assert.NotZero(t, token)
	logo.Info("loading")
	logo.ClearViewBadge(token)
	logo.Reset()
	logo.StylesChanged(nil)

	var nilLogo *ui.Logo
	assert.Zero(t, nilLogo.SetViewBadge("read-only graph", tcell.ColorYellow, tcell.ColorRed))
	nilLogo.ClearViewBadge(token)
	nilLogo.Reset()
	nilLogo.StylesChanged(nil)
}
