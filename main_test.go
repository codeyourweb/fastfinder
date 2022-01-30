package main

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/rivo/tview"
)

func TestConfigWindow(t *testing.T) {
	InitUI()
	go OpenFileDialog()
	time.Sleep(500 * time.Millisecond)

	if currentConfigWindowSelector == 0 {
		t.Fatal("OpenFileDialog failed to open")
	}
}

func TestMainWindow(t *testing.T) {
	InitUI()
	go MainWindow()
	time.Sleep(500 * time.Millisecond)

	if currentMainWindowSelector == 0 {
		t.Fatal("MainWindow failed to open")
	}
}

func TestConfigurationFileLoading(t *testing.T) {
	var config Configuration
	config.getConfiguration("tests/config_test_standard.yml")

	if len(config.Input.Content.Grep) == 0 || config.Input.Content.Grep[0] != "package main" {
		t.Fatal("config.getConfiguration fails to load and parse configuration file correctly")
	}
}

func TestRC4CipheredConfigurationFileLoading(t *testing.T) {
	var config Configuration
	config.getConfiguration("tests/config_test_ciphered.yml")

	if len(config.Input.Content.Grep) == 0 || config.Input.Content.Grep[0] != "package main" {
		t.Fatal("config.getConfiguration fails to load and parse configuration file correctly")
	}
}

func TestCleanUI(t *testing.T) {
	UIapp = tview.NewApplication()
	UIapp.ForceDraw()
	UIactive = false
	AppStarted = false
	UIapp.Stop()
	if UIactive || AppStarted {
		t.Fatal("Can't reset GUI app for further testing")
	}

	if runtime.GOOS == "linux" {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}
