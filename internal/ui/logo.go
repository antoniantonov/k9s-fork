// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package ui

import (
	"fmt"
	"strings"
	"sync"

	"github.com/derailed/k9s/internal/config"
	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
)

// LogoBadgeToken identifies the owner of a logo badge.
type LogoBadgeToken uint64

type logoStatusLevel uint8

const (
	logoStatusNone logoStatusLevel = iota
	logoStatusInfo
	logoStatusWarn
	logoStatusErr
)

type logoBadge struct {
	token LogoBadgeToken
	text  string
	fg    tcell.Color
	bg    tcell.Color
}

// Logo represents a K9s logo.
type Logo struct {
	*tview.Flex

	logo, status   *tview.TextView
	styles         *config.Styles
	badge          logoBadge
	nextBadgeToken LogoBadgeToken
	transientText  string
	transientLevel logoStatusLevel
	mx             sync.Mutex
}

// NewLogo returns a new logo.
func NewLogo(styles *config.Styles) *Logo {
	if styles == nil {
		styles = config.NewStyles()
	}
	l := Logo{
		Flex:   tview.NewFlex(),
		logo:   logo(),
		status: status(),
		styles: styles,
	}
	l.SetDirection(tview.FlexRow)
	l.AddItem(l.logo, 6, 1, false)
	l.AddItem(l.status, 1, 1, false)
	l.refreshLogo(styles.Body().LogoColor)
	l.SetBackgroundColor(styles.BgColor())
	styles.AddListener(&l)

	return &l
}

// Logo returns the logo viewer.
func (l *Logo) Logo() *tview.TextView {
	if l == nil {
		return nil
	}
	return l.logo
}

// Status returns the status viewer.
func (l *Logo) Status() *tview.TextView {
	if l == nil {
		return nil
	}
	return l.status
}

// SetViewBadge sets the persistent status badge and returns its ownership token.
func (l *Logo) SetViewBadge(text string, fg, bg tcell.Color) LogoBadgeToken {
	if l == nil {
		return 0
	}

	l.mx.Lock()
	defer l.mx.Unlock()

	l.nextBadgeToken++
	if l.nextBadgeToken == 0 {
		l.nextBadgeToken++
	}
	l.badge = logoBadge{
		token: l.nextBadgeToken,
		text:  text,
		fg:    fg,
		bg:    bg,
	}
	l.renderStatusLocked()

	return l.badge.token
}

// ClearViewBadge clears the persistent status badge owned by token.
func (l *Logo) ClearViewBadge(token LogoBadgeToken) {
	if l == nil || token == 0 {
		return
	}

	l.mx.Lock()
	defer l.mx.Unlock()
	if token != l.badge.token {
		return
	}

	l.badge = logoBadge{}
	l.renderStatusLocked()
}

// StylesChanged notifies the skin changed.
func (l *Logo) StylesChanged(s *config.Styles) {
	if l == nil {
		return
	}

	l.mx.Lock()
	defer l.mx.Unlock()
	if s == nil {
		s = l.styles
		if s == nil {
			s = config.NewStyles()
		}
	}
	l.styles = s
	l.renderLocked()
}

// IsBenchmarking checks if benchmarking is active or not.
func (l *Logo) IsBenchmarking() bool {
	if l == nil || l.Status() == nil {
		return false
	}
	txt := l.Status().GetText(true)
	return strings.Contains(txt, "Bench")
}

// Reset clears out the logo view and resets colors.
func (l *Logo) Reset() {
	if l == nil {
		return
	}

	l.mx.Lock()
	defer l.mx.Unlock()
	l.transientText = ""
	l.transientLevel = logoStatusNone
	l.renderLocked()
}

// Err displays a log error state.
func (l *Logo) Err(msg string) {
	l.update(msg, logoStatusErr)
}

// Warn displays a log warning state.
func (l *Logo) Warn(msg string) {
	l.update(msg, logoStatusWarn)
}

// Info displays a log info state.
func (l *Logo) Info(msg string) {
	l.update(msg, logoStatusInfo)
}

func (l *Logo) update(msg string, level logoStatusLevel) {
	if l == nil {
		return
	}

	l.mx.Lock()
	defer l.mx.Unlock()
	l.transientText = msg
	l.transientLevel = level
	l.renderStatusLocked()
	l.refreshLogoLocked(l.transientColorLocked())
}

func (l *Logo) renderLocked() {
	styles := l.stylesLocked()
	if l.Flex != nil {
		l.SetBackgroundColor(styles.BgColor())
	}
	if l.logo != nil {
		l.logo.SetBackgroundColor(styles.BgColor())
		if l.transientLevel == logoStatusNone {
			l.refreshLogoLocked(styles.Body().LogoColor)
		} else {
			l.refreshLogoLocked(l.transientColorLocked())
		}
	}
	l.renderStatusLocked()
}

func (l *Logo) renderStatusLocked() {
	if l.status == nil {
		return
	}

	styles := l.stylesLocked()
	if l.transientLevel != logoStatusNone {
		l.status.SetBackgroundColor(l.transientColorLocked().Color())
		l.status.SetText(
			fmt.Sprintf("[%s::b]%s", styles.Body().LogoColorMsg, l.transientText),
		)
		return
	}
	if l.badge.token != 0 {
		l.status.SetTextColor(l.badge.fg)
		l.status.SetBackgroundColor(l.badge.bg)
		l.status.SetText(tview.Escape(l.badge.text))
		return
	}

	l.status.SetTextColor(styles.FgColor())
	l.status.SetBackgroundColor(styles.BgColor())
	l.status.Clear()
}

func (l *Logo) transientColorLocked() config.Color {
	switch l.transientLevel {
	case logoStatusInfo:
		return l.stylesLocked().Body().LogoColorInfo
	case logoStatusWarn:
		return l.stylesLocked().Body().LogoColorWarn
	case logoStatusErr:
		return l.stylesLocked().Body().LogoColorError
	default:
		return l.stylesLocked().Body().LogoColor
	}
}

func (l *Logo) stylesLocked() *config.Styles {
	if l.styles == nil {
		l.styles = config.NewStyles()
	}
	return l.styles
}

func (l *Logo) refreshLogo(c config.Color) {
	l.mx.Lock()
	defer l.mx.Unlock()
	l.refreshLogoLocked(c)
}

func (l *Logo) refreshLogoLocked(c config.Color) {
	if l.logo == nil {
		return
	}
	l.logo.Clear()
	for i, s := range LogoSmall {
		_, _ = fmt.Fprintf(l.logo, "[%s::b]%s", c, s)
		if i+1 < len(LogoSmall) {
			_, _ = fmt.Fprintf(l.logo, "\n")
		}
	}
}

func logo() *tview.TextView {
	v := tview.NewTextView()
	v.SetWordWrap(false)
	v.SetWrap(false)
	v.SetTextAlign(tview.AlignLeft)
	v.SetDynamicColors(true)

	return v
}

func status() *tview.TextView {
	v := tview.NewTextView()
	v.SetWordWrap(false)
	v.SetWrap(false)
	v.SetTextAlign(tview.AlignCenter)
	v.SetDynamicColors(true)

	return v
}
