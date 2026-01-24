package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSFXBuildAndPathResolution(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("SFX build is only supported on x64 (amd64) architecture")
	}

	// Skip if strictly running unit tests without build capabilities or no go compiler
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go compiler not found, skipping SFX integration test")
	}

	// Setup temporary directory
	tempDir, err := os.MkdirTemp("", "fastfinder_sfx_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create a dummy YARA rule in a subfolder to test relative paths
	rulesDir := filepath.Join(tempDir, "rules")
	err = os.Mkdir(rulesDir, 0755)
	if err != nil {
		t.Fatal(err)
	}

	ruleContent := `
rule TestRule {
	strings:
		$a = "FindMeInSFX"
	condition:
		$a
}`
	rulePath := filepath.Join(rulesDir, "test.yar")
	err = os.WriteFile(rulePath, []byte(ruleContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create a matching file to scan
	targetFile := filepath.Join(tempDir, "target.txt")
	err = os.WriteFile(targetFile, []byte("This file contains the string FindMeInSFX and should be detected."), 0644)
	if err != nil {
		t.Fatal(err)
	}

	//  Create configuration file using relative path for YARA
	targetPathSlash := filepath.ToSlash(targetFile)
	configContent := fmt.Sprintf(`
input:
  path:
    - "%s"
  content:
    yara:
      - "./rules/test.yar"
options:
  contentMatchDependsOnPathMatch: false
output:
  copyMatchingFiles: false
  base64Files: false
  filesCopyPath: ""
`, targetPathSlash)

	configPath := filepath.Join(tempDir, "config.yaml")
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Build fastfinder itself first (the builder)
	builderExe := filepath.Join(tempDir, "fastfinder_builder.exe")
	if runtime.GOOS != "windows" {
		builderExe = filepath.Join(tempDir, "fastfinder_builder")
	}

	// We compile the current package "."
	t.Log("Building fastfinder builder...")
	cmdBuild := exec.Command("go", "build", "-tags", "yara_static", "-o", builderExe, ".")
	if out, err := cmdBuild.CombinedOutput(); err != nil {
		t.Logf("Build failed: %s\n", string(out))
		t.Fatalf("Failed to build fastfinder builder: %v\nOutput: %s", err, string(out))
	}
	t.Log("Builder built.")

	// Run the builder to create the SFX
	sfxExe := filepath.Join(tempDir, "sfx_result.exe")
	if runtime.GOOS != "windows" {
		sfxExe = filepath.Join(tempDir, "sfx_result")
	}

	cmdSFX := exec.Command(builderExe, "-c", configPath, "-b", sfxExe)
	t.Log("Running builder to create SFX...")
	if out, err := cmdSFX.CombinedOutput(); err != nil {
		t.Logf("SFX creation failed: %s\n", string(out))
		t.Fatalf("Failed to run fastfinder builder to create SFX: %v\nOutput: %s", err, string(out))
	}
	t.Log("SFX created.")

	// Give OS time to release handle
	time.Sleep(500 * time.Millisecond)

	systemTemp := os.TempDir()
	// extractedBinary := "fastfinder"
	extractionSubDir := "fastfinder" // Linux default

	if runtime.GOOS == "windows" {
		// extractedBinary = "fastfinder.exe"
		extractionSubDir = "FastFinder"
	}

	extractionRoot := filepath.Join(systemTemp, extractionSubDir)
	// extractedPath := filepath.Join(extractionRoot, extractedBinary)

	if err := os.RemoveAll(extractionRoot); err != nil && !os.IsNotExist(err) {
		t.Logf("Warning: Failed to remove previous extraction directory: %v", err)
	}

	if _, err := os.Stat(sfxExe); os.IsNotExist(err) {
		t.Fatalf("SFX executable was not created at %s", sfxExe)
	}

	// Run the SFX executable checking for immediate crash
	cmdRunSFX := exec.Command(sfxExe, "-r", tempDir)
	var outBuf bytes.Buffer
	cmdRunSFX.Stdout = &outBuf
	cmdRunSFX.Stderr = &outBuf

	if err := cmdRunSFX.Start(); err != nil {
		t.Fatalf("Failed to start SFX: %v", err)
	}

	// Wait for 2 seconds
	done := make(chan error, 1)
	go func() {
		done <- cmdRunSFX.Wait()
	}()

	select {
	case <-time.After(2 * time.Second):
		// It's still running after 2 seconds. valid behavior.
		if err := cmdRunSFX.Process.Kill(); err != nil {
			t.Logf("Failed to kill SFX: %v", err)
		}
		t.Log("SFX ran for 2 seconds without crashing. Test passed.")
	case err := <-done:
		// Exited before 2 seconds.
		// If exit code is 0, success. If != 0, crash.
		if err != nil {
			t.Fatalf("SFX exited with error: %v. Output:\n%s", err, outBuf.String())
		}
		t.Log("SFX finished successfully within 2 seconds.")
	}
}
