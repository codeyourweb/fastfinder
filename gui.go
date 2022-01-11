package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var UIapp = tview.NewApplication()
var UIselectedConfigPath string
var UItmpConfigPath string

// OpenFileDialog show a navigable tree view of the current directory.
func OpenFileDialog() {

	/*
	 * TEXTVIEW : Dialog title
	 */
	lblDialog := tview.NewTextView().SetTextAlign(tview.AlignCenter).SetText("Please select a yaml configuration file")

	/*
	 * TEXTVIEW : File preview
	 */
	textPreview := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetChangedFunc(func() {
			UIapp.Draw()
		})

	/*
	 * TREEVIEW : File and directory navigation
	 */
	rootDir, _ := os.Getwd()
	root := tview.NewTreeNode(rootDir).
		SetColor(tcell.ColorRed)
	treeView := tview.NewTreeView().
		SetRoot(root).
		SetCurrentNode(root)

	// function definition for adding files and directories to the treeview
	add := func(target *tview.TreeNode, p string) {
		files, err := ioutil.ReadDir(p)
		if err != nil {
			UIapp.Stop()
		}
		if filepath.Dir(p) != p {
			parentNode := tview.NewTreeNode("../ (" + filepath.Dir(p) + ")").SetReference(filepath.Dir(p)).SetSelectable(true).SetColor(tcell.ColorRed)
			target.AddChild(parentNode)
		}

		for _, file := range files {
			node := tview.NewTreeNode(file.Name()).
				SetReference(filepath.Join(p, file.Name())).
				SetSelectable(file.IsDir() || !file.IsDir() && (strings.HasSuffix(strings.ToLower(file.Name()), ".yml") || strings.HasSuffix(strings.ToLower(file.Name()), ".yaml")))
			if file.IsDir() {
				node.SetColor(tcell.ColorWhite)
			} else if !file.IsDir() && (strings.HasSuffix(strings.ToLower(file.Name()), ".yml") || strings.HasSuffix(strings.ToLower(file.Name()), ".yaml")) {
				node.SetColor(tcell.ColorGreen)
			} else {
				node.SetColor(tcell.ColorGrey)
			}

			target.AddChild(node)
		}
	}

	// Add the current directory as the root node
	add(root, rootDir)

	// If a file or directory was selected, open it.
	treeView.SetSelectedFunc(func(node *tview.TreeNode) {
		reference := node.GetReference()
		p := reference.(string)

		file, err := os.Open(p)
		if err != nil {
			return
		}

		fileInfo, err := file.Stat()
		if err != nil {
			return
		}

		if fileInfo.IsDir() {
			// directory tree drawing
			children := node.GetChildren()
			if len(children) == 0 {
				// Load and show files in this directory.
				add(node, p)
			} else {
				// Collapse if visible, expand if collapsed.
				node.SetExpanded(!node.IsExpanded())
			}
		} else {
			// file preview & selection
			if strings.HasSuffix(strings.ToLower(p), ".yml") || strings.HasSuffix(strings.ToLower(p), ".yaml") {
				if UItmpConfigPath == p {
					UIselectedConfigPath = p
					UIapp.Stop()
				}

				UItmpConfigPath = p

				d, err := os.ReadFile(p)
				if err != nil {
					return
				}

				textPreview.SetText("")
				fmt.Fprintf(textPreview, "[yellow]== Press Enter again to select this configuration file ==[white]\n\n%s", d)
				textPreview.ScrollTo(0, 0)
			}

		}

	})

	/*
	 * Building window
	 */
	grid := tview.NewGrid().SetRows(1, -1).SetColumns(-3, -2).SetBorders(true)
	grid.AddItem(lblDialog, 0, 0, 1, 2, 0, 0, false)
	grid.AddItem(treeView, 1, 0, 1, 1, 0, 0, true)
	grid.AddItem(textPreview, 1, 1, 1, 1, 0, 0, false)

	if err := UIapp.SetRoot(grid, true).SetFocus(treeView).Run(); err != nil {
		UIapp.Stop()
	}
}
