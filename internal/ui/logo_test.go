// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package ui_test

import (
	"strings"
	"sync"
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

func TestLogoCustomArt(t *testing.T) {
	v := ui.NewLogo(config.NewStyles())
	v.SetLogo("AB\n C")

	assert.Equal(t, "[#ffa500::b]AB\n[#ffa500::b] C\n", v.Logo().GetText(false))
}

func TestLogoRendering(t *testing.T) {
	for name, tc := range map[string]struct {
		art  string
		rows []string
	}{
		"brackets":             {"[red] [x] [::b]", []string{"[red] [x] [::b]"}},
		"tabs and indentation": {" A\tB", []string{" A    B"}},
		"CRLF":                 {" A\r\nB\r\n", []string{" A", "B"}},
		"wide art":             {strings.Repeat("A", 30), []string{strings.Repeat("A", ui.LogoWidth)}},
		"partial wide rune":    {strings.Repeat("A", 25) + "\u754c", []string{strings.Repeat("A", 25)}},
		"tall art":             {"1\n2\n3\n4\n5\n6\n7\n8", []string{"1", "2", "3", "4", "5", "6"}},
	} {
		t.Run(name, func(t *testing.T) {
			screen := tcell.NewSimulationScreen("UTF-8")
			require.NoError(t, screen.Init())
			defer screen.Fini()
			screen.SetSize(ui.LogoWidth, ui.LogoArtHeight+1)
			v := ui.NewLogo(config.NewStyles())
			v.SetRect(0, 0, ui.LogoWidth, ui.LogoArtHeight+1)
			v.SetLogo(tc.art)
			v.Draw(screen)
			for y, want := range tc.rows {
				var row strings.Builder
				for x := range ui.LogoWidth {
					r, _, style, _ := screen.GetContent(x, y)
					row.WriteRune(r)
					if x < len(want) {
						fg, _, _ := style.Decompose()
						assert.Equal(t, config.NewStyles().Body().LogoColor.Color(), fg)
					}
				}
				assert.Equal(t, want, strings.TrimRight(row.String(), " "))
			}
		})
	}
}

func TestLogoWideRunesAndCombiningCharacters(t *testing.T) {
	screen := tcell.NewSimulationScreen("UTF-8")
	require.NoError(t, screen.Init())
	defer screen.Fini()
	screen.SetSize(ui.LogoWidth, ui.LogoArtHeight+1)
	v := ui.NewLogo(config.NewStyles())
	v.SetRect(0, 0, ui.LogoWidth, ui.LogoArtHeight+1)
	v.SetLogo(strings.Repeat("\u754c", 13) + "X\ne\u0301\t\u754c")
	v.Draw(screen)
	for x := 0; x < ui.LogoWidth; x += 2 {
		r, _, _, width := screen.GetContent(x, 0)
		assert.Equal(t, '\u754c', r)
		assert.Equal(t, 2, width)
	}
	r, combining, _, _ := screen.GetContent(0, 1)
	assert.Equal(t, 'e', r)
	assert.Equal(t, []rune{'\u0301'}, combining)
	r, _, _, _ = screen.GetContent(5, 1)
	assert.Equal(t, '\u754c', r)
}

func TestLogoFixedFootprint(t *testing.T) {
	screen := tcell.NewSimulationScreen("UTF-8")
	require.NoError(t, screen.Init())
	defer screen.Fini()
	screen.SetSize(ui.LogoWidth, ui.LogoArtHeight+1)
	v := ui.NewLogo(config.NewStyles())
	v.SetLogo("A\nB\nC\nD")
	v.Info("status")
	v.SetRect(0, 0, ui.LogoWidth, ui.LogoArtHeight+1)
	v.Draw(screen)
	_, _, _, artHeight := v.Logo().GetRect()
	_, statusY, _, statusHeight := v.Status().GetRect()
	assert.Equal(t, ui.LogoArtHeight, artHeight)
	assert.Equal(t, ui.LogoArtHeight, statusY)
	assert.Equal(t, 1, statusHeight)
	r, _, _, _ := screen.GetContent(0, 0)
	assert.Equal(t, 'A', r)
}

func TestLogoConcurrentUpdates(t *testing.T) {
	styles := config.NewStyles()
	v := ui.NewLogo(styles)
	screen := tcell.NewSimulationScreen("UTF-8")
	require.NoError(t, screen.Init())
	defer screen.Fini()
	screen.SetSize(ui.LogoWidth, ui.LogoArtHeight+1)
	v.SetRect(0, 0, ui.LogoWidth, ui.LogoArtHeight+1)
	var wg sync.WaitGroup
	for _, update := range []func(){
		func() { v.SetLogo("[red]\t\u754c\nsecond") },
		func() { v.StylesChanged(styles) },
		func() { v.Info("Bench"); v.Warn("warn"); v.Err("err"); v.Reset() },
		func() {
			token := v.SetViewBadge("read-only graph", tcell.ColorYellow, tcell.ColorRed)
			v.ClearViewBadge(token)
		},
		func() { v.IsBenchmarking() },
		func() { v.Draw(screen) },
	} {
		wg.Go(func() {
			for range 100 {
				update()
			}
		})
	}
	wg.Wait()
}

func TestLogoCustomArtFallsBack(t *testing.T) {
	v := ui.NewLogo(config.NewStyles())
	v.SetLogo(" \n\t\n")

	const elogo = "[#ffa500::b] ____  __ ________       \n[#ffa500::b]|    |/  /   __   \\______\n[#ffa500::b]|       /\\____    /  ___/\n[#ffa500::b]|    \\   \\  /    /\\___  \\\n[#ffa500::b]|____|\\__ \\/____//____  /\n[#ffa500::b]         \\/           \\/ \n"
	assert.Equal(t, elogo, v.Logo().GetText(false))
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

func TestLogoCustomArtPreservesViewBadgeAndTransientStatus(t *testing.T) {
	styles := config.NewStyles()
	for name, tc := range map[string]struct {
		update func(*ui.Logo, string)
		color  config.Color
	}{
		"info": {(*ui.Logo).Info, styles.Body().LogoColorInfo},
		"warn": {(*ui.Logo).Warn, styles.Body().LogoColorWarn},
		"err":  {(*ui.Logo).Err, styles.Body().LogoColorError},
	} {
		t.Run(name, func(t *testing.T) {
			v := ui.NewLogo(styles)
			token := v.SetViewBadge("read-only graph", tcell.ColorYellow, tcell.ColorRed)
			v.SetLogo("CUSTOM")
			rows := renderLogo(t, v)
			assert.Equal(t, "CUSTOM", rowText(rows[0]))
			assert.Equal(t, "read-only graph", rowText(rows[ui.LogoArtHeight]))
			assertRowStyle(t, rows[ui.LogoArtHeight], tcell.ColorYellow, tcell.ColorRed)

			tc.update(v, "loading")
			v.SetLogo("UPDATED")
			rows = renderLogo(t, v)
			assert.Equal(t, "UPDATED", rowText(rows[0]))
			assertRowForeground(t, rows[0], tc.color.Color())
			assert.Equal(t, "loading", rowText(rows[ui.LogoArtHeight]))
			assertRowStyle(t, rows[ui.LogoArtHeight], styles.Body().LogoColorMsg.Color(), tc.color.Color())

			v.StylesChanged(styles)
			rows = renderLogo(t, v)
			assert.Equal(t, "UPDATED", rowText(rows[0]))
			assertRowForeground(t, rows[0], tc.color.Color())
			assert.Equal(t, "loading", rowText(rows[ui.LogoArtHeight]))

			v.Reset()
			rows = renderLogo(t, v)
			assert.Equal(t, "UPDATED", rowText(rows[0]))
			assertRowForeground(t, rows[0], styles.Body().LogoColor.Color())
			assert.Equal(t, "read-only graph", rowText(rows[ui.LogoArtHeight]))
			assertRowStyle(t, rows[ui.LogoArtHeight], tcell.ColorYellow, tcell.ColorRed)

			v.ClearViewBadge(token)
			assert.Empty(t, rowText(renderLogo(t, v)[ui.LogoArtHeight]))
		})
	}
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
	logo.SetLogo("CUSTOM")
	logo.Info("loading")
	logo.ClearViewBadge(token)
	logo.Reset()
	logo.StylesChanged(nil)

	var nilLogo *ui.Logo
	assert.Zero(t, nilLogo.SetViewBadge("read-only graph", tcell.ColorYellow, tcell.ColorRed))
	nilLogo.SetLogo("CUSTOM")
	nilLogo.ClearViewBadge(token)
	nilLogo.Reset()
	nilLogo.StylesChanged(nil)
}
