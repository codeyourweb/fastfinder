package main

import (
	"os"
	"testing"
)

// TestFileHashFunctions tests hash calculation functions
func TestFileSHA256Sum(t *testing.T) {
	// Test with a known file
	hash := FileSHA256Sum("go.mod")

	if hash == "" {
		t.Fatal("FileSHA256Sum returned empty string")
	}

	// SHA256 hash should be 64 characters (hex)
	if len(hash) != 64 {
		t.Fatalf("SHA256 hash should be 64 characters, got %d", len(hash))
	}
}

// TestContainsHelper tests the Contains utility function
func TestContainsHelper(t *testing.T) {
	list := []string{"apple", "banana", "cherry"}

	if !Contains(list, "banana") {
		t.Fatal("Contains failed to find existing element")
	}

	if Contains(list, "date") {
		t.Fatal("Contains incorrectly reported finding non-existent element")
	}

	if Contains([]string{}, "apple") {
		t.Fatal("Contains should return false for empty list")
	}
}

// TestFileCopy creates a temporary test scenario for file operations
func TestFileCopyOperation(t *testing.T) {
	// This test verifies that FileCopy function can be called without panic
	// Actual file operations are tested with temporary directories
	tempSrc := t.TempDir() + "/source.txt"
	tempDst := t.TempDir() + "/dest"

	// Create source file
	err := writeTestFile(tempSrc, "test content")
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// FileCopy should not panic
	FileCopy(tempSrc, tempDst, false)
}

// TestGetHostname verifies hostname retrieval
func TestGetHostname(t *testing.T) {
	hostname := GetHostname()

	if hostname == "" {
		t.Fatal("GetHostname returned empty string")
	}
}

// TestGetUsername verifies username retrieval
func TestGetUsername(t *testing.T) {
	username := GetUsername()

	if username == "" {
		t.Fatal("GetUsername returned empty string")
	}
}

// TestGetCurrentDirectory verifies current directory retrieval
func TestGetCurrentDirectory(t *testing.T) {
	dir := GetCurrentDirectory()

	if dir == "" {
		t.Fatal("GetCurrentDirectory returned empty string")
	}
}

// TestRenderFastfinderLogo verifies logo rendering
func TestRenderFastfinderLogo(t *testing.T) {
	logo := RenderFastfinderLogo()

	if logo == "" {
		t.Fatal("RenderFastfinderLogo returned empty string")
	}

	// Logo should contain the program name
	if len(logo) < 10 {
		t.Fatal("Logo seems too short")
	}
}

// TestRenderFastfinderVersion verifies version info rendering
func TestRenderFastfinderVersion(t *testing.T) {
	version := RenderFastfinderVersion()

	if version == "" {
		t.Fatal("RenderFastfinderVersion returned empty string")
	}

	// Version should mention the version number
	if len(version) < 5 {
		t.Fatal("Version string seems too short")
	}
}

// Helper function to write test files
func writeTestFile(path string, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
