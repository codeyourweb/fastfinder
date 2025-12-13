package main

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gioui.org/app"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/sqweek/dialog"
)

type GuiApp struct {
	window     *app.Window
	theme      *material.Theme
	configPath string
	isScanning bool
	cancel     context.CancelFunc
	mutex      sync.RWMutex

	// UI state
	configButton widget.Clickable
	startButton  widget.Clickable
	stopButton   widget.Clickable
	clearButton  widget.Clickable
	themeButton  widget.Clickable
	githubLink   widget.Clickable
	matchesTab   widget.Clickable
	infoTab      widget.Clickable
	errorsTab    widget.Clickable
	tabs         widget.Enum

	// Text editors for output display
	matchLog  widget.Editor
	logOutput widget.Editor
	errorLog  widget.Editor

	// Content and counters
	matchText    string
	logText      string
	errorText    string
	matchCount   int
	infoCount    int
	errorCount   int
	resultsCount int
	statusText   string
	configLabel  string

	// Theme
	isDarkMode bool
	colors     struct {
		primary    color.NRGBA
		secondary  color.NRGBA
		accent     color.NRGBA
		error      color.NRGBA
		success    color.NRGBA
		background color.NRGBA
		card       color.NRGBA
		text       color.NRGBA
	}
}

// NewGuiApp creates a new GUI application
func NewGuiApp() *GuiApp {
	w := &app.Window{}
	w.Option(app.Title("FastFinder v" + FASTFINDER_VERSION + " - Incident Response Tool"))
	w.Option(app.Size(1200, 800))
	w.Option(app.Maximized.Option()) // Start with maximized window

	g := &GuiApp{
		window:      w,
		theme:       material.NewTheme(),
		statusText:  "Ready to scan",
		configLabel: "No configuration selected",
		tabs:        widget.Enum{Value: "matches"},
		isDarkMode:  true,
	}
	g.updateColors()
	return g
}

// updateColors updates the color scheme based on the current theme
func (g *GuiApp) updateColors() {
	if g.isDarkMode {
		g.colors.primary = color.NRGBA{R: 66, G: 165, B: 245, A: 255}
		g.colors.secondary = color.NRGBA{R: 158, G: 158, B: 158, A: 255}
		g.colors.accent = color.NRGBA{R: 255, G: 235, B: 59, A: 255}
		g.colors.error = color.NRGBA{R: 244, G: 67, B: 54, A: 255}
		g.colors.success = color.NRGBA{R: 76, G: 175, B: 80, A: 255}
		g.colors.background = color.NRGBA{R: 18, G: 18, B: 18, A: 255}
		g.colors.card = color.NRGBA{R: 33, G: 33, B: 33, A: 255}
		g.colors.text = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
	} else {
		g.colors.primary = color.NRGBA{R: 33, G: 150, B: 243, A: 255}
		g.colors.secondary = color.NRGBA{R: 96, G: 125, B: 139, A: 255}
		g.colors.accent = color.NRGBA{R: 255, G: 193, B: 7, A: 255}
		g.colors.error = color.NRGBA{R: 244, G: 67, B: 54, A: 255}
		g.colors.success = color.NRGBA{R: 76, G: 175, B: 80, A: 255}
		g.colors.background = color.NRGBA{R: 250, G: 250, B: 250, A: 255}
		g.colors.card = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
		g.colors.text = color.NRGBA{R: 33, G: 33, B: 33, A: 255}
	}
}

// Run starts the GUI application
func (g *GuiApp) Run() {
	go func() {
		for {
			switch e := g.window.Event().(type) {
			case app.DestroyEvent:
				if g.isScanning && g.cancel != nil {
					g.cancel()
				}
				return
			case app.FrameEvent:
				gtx := app.NewContext(&op.Ops{}, e)
				g.layout(gtx)
				e.Frame(gtx.Ops)
			}
		}
	}()
	app.Main()
}

// layout defines the main UI layout
func (g *GuiApp) layout(gtx layout.Context) layout.Dimensions {
	rect := clip.Rect{Max: gtx.Constraints.Max}
	paint.FillShape(gtx.Ops, g.colors.background, rect.Op())

	g.handleInputs(gtx)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(g.layoutHeader),
		layout.Rigid(g.layoutConfigCard),
		layout.Rigid(g.layoutControlPanel),
		layout.Rigid(g.layoutStatusBar),
		layout.Flexed(1, g.layoutContentTabs),
		layout.Rigid(g.layoutFooter),
	)
}

// layoutHeader draws the application header
func (g *GuiApp) layoutHeader(gtx layout.Context) layout.Dimensions {
	headerHeight := gtx.Dp(80)
	headerRect := clip.Rect{Max: image.Pt(gtx.Constraints.Max.X, headerHeight)}
	paint.FillShape(gtx.Ops, g.colors.primary, headerRect.Op())

	return layout.Inset{Top: 20, Bottom: 20, Left: 30, Right: 30}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						title := material.H4(g.theme, "FastFinder v"+FASTFINDER_VERSION)
						title.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
						title.Alignment = text.Start
						return title.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						subtitle := material.Body2(g.theme, "Incident Response Tool")
						subtitle.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 180}
						return subtitle.Layout(gtx)
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						themeText := "Light"
						if !g.isDarkMode {
							themeText = "Dark"
						}
						btn := material.Button(g.theme, &g.themeButton, themeText)
						btn.Background = color.NRGBA{R: 255, G: 255, B: 255, A: 100}
						btn.Color = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
						return btn.Layout(gtx)
					}),
				)
			}),
		)
	})
}

// layoutConfigCard draws a modern configuration card
func (g *GuiApp) layoutConfigCard(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Top: 20, Bottom: 10, Left: 30, Right: 30}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		// Card background with theme colors
		cardRect := clip.RRect{
			Rect: image.Rectangle{Max: image.Pt(gtx.Constraints.Max.X, gtx.Dp(120))},
			NE:   gtx.Dp(12), NW: gtx.Dp(12), SE: gtx.Dp(12), SW: gtx.Dp(12),
		}
		paint.FillShape(gtx.Ops, g.colors.card, cardRect.Op(gtx.Ops))

		return layout.Inset{Top: 20, Bottom: 20, Left: 25, Right: 25}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				// Card title
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					title := material.H6(g.theme, "Configuration")
					title.Color = g.colors.text
					return title.Layout(gtx)
				}),

				layout.Rigid(layout.Spacer{Height: unit.Dp(10)}.Layout),

				// Configuration controls
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							btn := material.Button(g.theme, &g.configButton, "Select Config File")
							btn.Background = g.colors.primary
							btn.CornerRadius = unit.Dp(8)
							return btn.Layout(gtx)
						}),

						layout.Rigid(layout.Spacer{Width: unit.Dp(15)}.Layout),

						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							g.mutex.RLock()
							configText := g.configLabel
							g.mutex.RUnlock()

							label := material.Body1(g.theme, configText)
							if g.configPath != "" {
								label.Color = g.colors.success
							} else {
								label.Color = g.colors.error
							}
							return label.Layout(gtx)
						}),
					)
				}),
			)
		})
	})
}

// layoutControlPanel draws a modern control panel
func (g *GuiApp) layoutControlPanel(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Top: 10, Bottom: 10, Left: 30, Right: 30}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		// Control panel card
		cardRect := clip.RRect{
			Rect: image.Rectangle{Max: image.Pt(gtx.Constraints.Max.X, gtx.Dp(80))},
			NE:   gtx.Dp(12), NW: gtx.Dp(12), SE: gtx.Dp(12), SW: gtx.Dp(12),
		}
		paint.FillShape(gtx.Ops, g.colors.card, cardRect.Op(gtx.Ops))

		return layout.Inset{Top: 15, Bottom: 15, Left: 25, Right: 25}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				// Start button
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					startBtn := material.Button(g.theme, &g.startButton, "Start Scan")
					if g.configPath == "" || g.isScanning {
						gtx = gtx.Disabled()
					}
					startBtn.Background = g.colors.success
					startBtn.CornerRadius = unit.Dp(8)
					return layout.Inset{Right: unit.Dp(15)}.Layout(gtx, startBtn.Layout)
				}),

				// Stop button
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					stopBtn := material.Button(g.theme, &g.stopButton, "Stop")
					if !g.isScanning {
						gtx = gtx.Disabled()
					}
					stopBtn.Background = g.colors.error
					stopBtn.CornerRadius = unit.Dp(8)
					return layout.Inset{Right: unit.Dp(15)}.Layout(gtx, stopBtn.Layout)
				}),

				// Clear button
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					clearBtn := material.Button(g.theme, &g.clearButton, "Clear")
					if g.isScanning {
						gtx = gtx.Disabled()
					}
					clearBtn.Background = g.colors.secondary
					clearBtn.CornerRadius = unit.Dp(8)
					return clearBtn.Layout(gtx)
				}),

				layout.Flexed(1, layout.Spacer{}.Layout),

				// Results counter
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					g.mutex.RLock()
					resultsText := fmt.Sprintf("Results: %d", g.resultsCount)
					g.mutex.RUnlock()

					label := material.H6(g.theme, resultsText)
					if g.resultsCount > 0 {
						label.Color = g.colors.primary
					} else {
						label.Color = g.colors.secondary
					}
					return label.Layout(gtx)
				}),
			)
		})
	})
}

// layoutStatusBar draws a modern status bar with progress
func (g *GuiApp) layoutStatusBar(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Top: 5, Bottom: 15, Left: 30, Right: 30}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			// Status text
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				g.mutex.RLock()
				status := g.statusText
				g.mutex.RUnlock()

				// Status icon based on state
				var statusIcon string
				var statusColor color.NRGBA

				if g.isScanning {
					statusIcon = "[SCANNING]"
					statusColor = g.colors.primary
				} else if g.configPath != "" {
					statusIcon = "[READY]"
					statusColor = g.colors.success
				} else {
					statusIcon = "[WAITING]"
					statusColor = g.colors.error
				}

				label := material.Body1(g.theme, fmt.Sprintf("%s %s", statusIcon, status))
				label.Color = statusColor
				return label.Layout(gtx)
			}),

			// Progress bar when scanning
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if !g.isScanning {
					return layout.Dimensions{}
				}

				// Progress bar background
				progressHeight := gtx.Dp(6)
				backgroundRect := clip.RRect{
					Rect: image.Rectangle{Max: image.Pt(gtx.Constraints.Max.X, progressHeight)},
					NE:   gtx.Dp(3), NW: gtx.Dp(3), SE: gtx.Dp(3), SW: gtx.Dp(3),
				}
				paint.FillShape(gtx.Ops, color.NRGBA{R: 230, G: 230, B: 230, A: 255}, backgroundRect.Op(gtx.Ops))

				// Progress bar fill (indeterminate animation)
				progressWidth := int(float32(gtx.Constraints.Max.X) * 0.3) // 30% width for animation
				progressRect := clip.RRect{
					Rect: image.Rectangle{Max: image.Pt(progressWidth, progressHeight)},
					NE:   gtx.Dp(3), NW: gtx.Dp(3), SE: gtx.Dp(3), SW: gtx.Dp(3),
				}
				paint.FillShape(gtx.Ops, g.colors.primary, progressRect.Op(gtx.Ops))

				return layout.Dimensions{Size: image.Pt(gtx.Constraints.Max.X, progressHeight)}
			}),
		)
	})
}

// layoutContentTabs draws modern content tabs
func (g *GuiApp) layoutContentTabs(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Top: 5, Left: 30, Right: 30, Bottom: 20}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		// Main content card
		cardRect := clip.RRect{
			Rect: image.Rectangle{Max: gtx.Constraints.Max},
			NE:   gtx.Dp(12), NW: gtx.Dp(12), SE: gtx.Dp(12), SW: gtx.Dp(12),
		}
		paint.FillShape(gtx.Ops, g.colors.card, cardRect.Op(gtx.Ops))

		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			// Modern tab bar
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: 15, Left: 20, Right: 20}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Rigid(g.createModernTab("matches", "Matches")),
						layout.Rigid(g.createModernTab("information", "Information")),
						layout.Rigid(g.createModernTab("errors", "Errors")),
					)
				})
			}),

			// Tab content
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Top: 10, Bottom: 15, Left: 20, Right: 20}.Layout(gtx, g.layoutTabContent)
			}),
		)
	})
}

// createModernTab creates a modern tab button with counters
func (g *GuiApp) createModernTab(value, baseText string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		var btn *widget.Clickable
		var count int

		// Select the right clickable and count based on tab value
		switch value {
		case "matches":
			btn = &g.matchesTab
			count = g.matchCount
		case "information":
			btn = &g.infoTab
			count = g.infoCount
		case "errors":
			btn = &g.errorsTab
			count = g.errorCount
		default:
			btn = &widget.Clickable{}
		}

		isActive := g.tabs.Value == value

		// Check for click
		if btn.Clicked(gtx) {
			g.tabs.Value = value
		}

		// Create text with counter
		text := fmt.Sprintf("%s (%d)", baseText, count)

		// Tab styling based on theme
		var bgColor color.NRGBA
		var textColor color.NRGBA

		if isActive {
			bgColor = g.colors.primary
			textColor = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
		} else {
			bgColor = g.colors.card
			textColor = g.colors.text
		}

		// Create button material
		materialBtn := material.Button(g.theme, btn, text)
		materialBtn.Background = bgColor
		materialBtn.Color = textColor
		materialBtn.CornerRadius = unit.Dp(8)

		return materialBtn.Layout(gtx)
	}
}

// layoutTabContent draws the content of the selected tab
func (g *GuiApp) layoutTabContent(gtx layout.Context) layout.Dimensions {
	g.mutex.RLock()
	matchText := g.matchText
	logText := g.logText
	errorText := g.errorText
	g.mutex.RUnlock()

	switch g.tabs.Value {
	case "matches":
		if matchText == "" {
			matchText = "No matches found yet.\nFiles matching your criteria will appear here.\n\nCurrent scan status: " + g.statusText
		}
		g.matchLog.SetText(matchText)
		return g.layoutEditor(gtx, &g.matchLog)
	case "information":
		if logText == "" {
			logText = "Waiting for scan to start...\nScan information and progress will appear here.\n\nTip: Select a configuration file and click Start Scan."
		}
		g.logOutput.SetText(logText)
		return g.layoutEditor(gtx, &g.logOutput)
	case "errors":
		if errorText == "" {
			errorText = "No errors yet.\nAny scan errors or warnings will appear here.\n\nIf you see this message, everything is working correctly!"
		}
		g.errorLog.SetText(errorText)
		return g.layoutEditor(gtx, &g.errorLog)
	default:
		// Default fallback content
		defaultEditor := widget.Editor{ReadOnly: true}
		defaultEditor.SetText("Select a tab above to view content.")
		return g.layoutEditor(gtx, &defaultEditor)
	}
}

// layoutEditor draws a text editor
func (g *GuiApp) layoutEditor(gtx layout.Context, editor *widget.Editor) layout.Dimensions {
	editor.ReadOnly = true
	border := widget.Border{
		Color: g.colors.secondary,
		Width: 1,
	}
	return border.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: 5, Bottom: 5, Left: 5, Right: 5}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			// Create editor with proper theme colors
			editorMaterial := material.Editor(g.theme, editor, "")
			editorMaterial.Color = g.colors.text
			editorMaterial.HintColor = g.colors.secondary

			// Create a scrollbar layout with vertical scrolling
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return editorMaterial.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					// Add a thin vertical scrollbar on the right
					return layout.Dimensions{Size: image.Pt(8, gtx.Constraints.Max.Y)}
				}),
			)
		})
	})
}

// handleInputs processes user inputs
func (g *GuiApp) handleInputs(gtx layout.Context) {
	if g.configButton.Clicked(gtx) {
		g.selectConfigFile()
	}

	if g.startButton.Clicked(gtx) && !g.isScanning && g.configPath != "" {
		g.startScan()
	}

	if g.stopButton.Clicked(gtx) && g.isScanning {
		g.stopScan()
	}

	if g.clearButton.Clicked(gtx) && !g.isScanning {
		g.clearOutputs()
		g.updateStatus("Output cleared")
	}

	if g.themeButton.Clicked(gtx) {
		g.isDarkMode = !g.isDarkMode
		g.updateColors()
		g.window.Invalidate()
	}

	if g.githubLink.Clicked(gtx) {
		g.updateStatus("Visit: https://github.com/codeyourweb/fastfinder")
	}
}

// selectConfigFile opens a native file dialog to select the configuration file
func (g *GuiApp) selectConfigFile() {
	go func() {
		// Use native file dialog
		filename, err := dialog.File().
			Filter("YAML files", "yml", "yaml").
			Filter("All files", "*").
			Title("Select FastFinder Configuration File").
			Load()

		if err != nil {
			// User cancelled or error occurred
			return
		}

		// Update configuration path
		g.mutex.Lock()
		g.configPath = filename
		g.configLabel = fmt.Sprintf("✓ %s", filepath.Base(filename))
		g.statusText = "Configuration loaded successfully"
		g.mutex.Unlock()
	}()
}

// startScan begins the scanning process
func (g *GuiApp) startScan() {
	if g.configPath == "" {
		g.updateStatus("Error: No configuration file selected")
		return
	}

	if _, err := os.Stat(g.configPath); os.IsNotExist(err) {
		g.updateStatus(fmt.Sprintf("Error: Configuration file not found: %s", g.configPath))
		return
	}

	g.isScanning = true
	g.clearOutputs()
	g.updateStatus("Initializing scan...")

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel

	// Initialize log
	g.logInfo("=== FastFinder Scan Started ===")
	g.logInfo(fmt.Sprintf("Configuration: %s", filepath.Base(g.configPath)))
	g.logInfo("Initializing scan parameters...")

	// Run scan in goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				g.updateStatus(fmt.Sprintf("Scan crashed: %v", r))
				g.logError(fmt.Sprintf("Scan crashed: %v", r))
			}
			g.isScanning = false
		}()

		select {
		case <-ctx.Done():
			g.updateStatus("Scan cancelled")
			return
		default:
			g.runRealScan()
		}
	}()
}

// stopScan stops the current scanning process
func (g *GuiApp) stopScan() {
	if g.cancel != nil {
		g.cancel()
	}
	g.isScanning = false
	g.updateStatus("Scan stopped by user")
}

// runRealScan executes the real FastFinder scanning engine
func (g *GuiApp) runRealScan() {
	defer func() {
		g.isScanning = false
		if g.resultsCount > 0 {
			g.updateStatus(fmt.Sprintf("Scan completed - %d matches found", g.resultsCount))
		} else {
			g.updateStatus("Scan completed - no matches found")
		}
	}()

	// Load configuration
	var config Configuration
	defer func() {
		if r := recover(); r != nil {
			g.updateStatus(fmt.Sprintf("Configuration error: %v", r))
			g.logError(fmt.Sprintf("Failed to load configuration: %v", r))
			return
		}
	}()

	g.updateStatus("Loading configuration...")
	config.getConfiguration(g.configPath)
	g.logInfo("Configuration loaded successfully")

	// Set up GUI logging
	guiLogOutput = g.handleLogMessage
	oldUIActive := UIactive
	UIactive = false

	defer func() {
		UIactive = oldUIActive
		guiLogOutput = nil
		if r := recover(); r != nil {
			g.updateStatus(fmt.Sprintf("Scan failed: %v", r))
			g.logError(fmt.Sprintf("Scan crashed: %v", r))
		}
	}()

	// Run the main FastFinder routine
	g.updateStatus("Starting scan...")
	MainFastfinderRoutine(config, g.configPath, true, "", false, 3)
}

// handleLogMessage handles log output from the FastFinder engine
func (g *GuiApp) handleLogMessage(logType int, prefix string, message ...interface{}) {
	aString := make([]string, len(message))
	for i, v := range message {
		aString[i] = fmt.Sprintf("%v", v)
	}
	text := strings.Join(aString, " ")

	switch logType {
	case LOG_ERROR:
		g.logError(text)
	case LOG_ALERT:
		g.logMatch(text)
	default:
		g.logInfo(text)
	}
}

// logInfo adds an info message
func (g *GuiApp) logInfo(msg string) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.logText += "\n[INFO] " + msg
	g.infoCount++
}

// logMatch adds a match message
func (g *GuiApp) logMatch(msg string) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.matchText += "\n[MATCH] " + msg
	g.matchCount++
	g.resultsCount++
}

// logError adds an error message
func (g *GuiApp) logError(msg string) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.errorText += "\n[ERROR] " + msg
	g.errorCount++
}

// updateStatus updates the status text safely
func (g *GuiApp) updateStatus(status string) {
	g.mutex.Lock()
	g.statusText = status
	g.mutex.Unlock()
}

// clearOutputs clears all output text areas
func (g *GuiApp) clearOutputs() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.logText = ""
	g.matchText = ""
	g.errorText = ""
	g.resultsCount = 0
	g.matchCount = 0
	g.infoCount = 0
	g.errorCount = 0
}

// layoutFooter draws the footer
func (g *GuiApp) layoutFooter(gtx layout.Context) layout.Dimensions {
	return layout.Inset{Top: 5, Bottom: 10, Left: 30, Right: 30}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		footerRect := clip.Rect{Max: image.Pt(gtx.Constraints.Max.X, gtx.Dp(30))}
		footerBgColor := g.colors.card
		if g.isDarkMode {
			footerBgColor = color.NRGBA{R: 25, G: 25, B: 25, A: 255}
		}
		paint.FillShape(gtx.Ops, footerBgColor, footerRect.Op())

		return layout.Inset{Top: 8, Bottom: 8, Left: 15, Right: 15}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					label := material.Caption(g.theme, fmt.Sprintf("FastFinder v%s - Jean-Pierre GARNIER - ", FASTFINDER_VERSION))
					label.Color = g.colors.secondary
					return label.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					link := material.Button(g.theme, &g.githubLink, "github.com/codeyourweb/fastfinder")
					link.Background = color.NRGBA{A: 0}
					link.Color = g.colors.primary
					link.Inset = layout.Inset{}
					return link.Layout(gtx)
				}),
				layout.Flexed(1, layout.Spacer{}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					label := material.Caption(g.theme, "Incident Response & Forensic Tool")
					label.Color = g.colors.secondary
					return label.Layout(gtx)
				}),
			)
		})
	})
}
