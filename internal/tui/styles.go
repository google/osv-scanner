package tui

import (
	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/compat"
)

var (
	ColorPrimary  = lipgloss.Color("#e62129") // Red, from the OSV logo :)
	ColorDisabled = compat.AdaptiveColor{     // Grey
		Light: lipgloss.Color("250"),
		Dark:  lipgloss.Color("238"),
	}
)

var (
	SelectedTextStyle = lipgloss.NewStyle().Foreground(ColorPrimary)
	DisabledTextStyle = lipgloss.NewStyle().Foreground(ColorDisabled)
)

// View dimensions
// width / height refers to the internal text area of the view
// i.e. excluding the border and the padding
const (
	ViewMinHeight = 20 // the minimum internal height the view can be
	ViewVPad      = 1  // the vertical padding of the view

	ViewMinWidth = 60  // the minimum internal width the view can be
	ViewWidthPct = 0.4 // percentage of terminal internal width the main view should occupy
	ViewHPad     = 2   // the horizontal padding of the view
)
