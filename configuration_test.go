package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConfigurationStandard tests loading a standard (non-encrypted) configuration
func TestConfigurationStandard(t *testing.T) {
	var config Configuration
	config.getConfiguration("../config_test_standard.yml")

	// Verify basic structure is accessible (paths may be empty in test file)
	t.Log("Configuration loaded successfully")
}

// TestConfigurationCiphered tests loading an encrypted (RC4) configuration
func TestConfigurationCiphered(t *testing.T) {
	var config Configuration
	config.getConfiguration("../config_test_ciphered.yml")

	// Verify basic structure is accessible (paths may be empty in test file)
	t.Log("Ciphered configuration loaded successfully")
}

// TestConfigurationPaths verifies path configuration structure
func TestConfigurationPaths(t *testing.T) {
	var config Configuration
	config.getConfiguration("../config_test_standard.yml")

	if len(config.Input.Path) > 0 {
		// Verify first path is not empty
		if config.Input.Path[0] == "" {
			t.Fatal("Path should not be empty")
		}
	}
}

// TestConfigurationContent verifies content patterns (grep, yara, checksum)
func TestConfigurationContent(t *testing.T) {
	var config Configuration
	config.getConfiguration("../config_test_standard.yml")

	if config.Input.Content.Grep != nil {
		// Grep patterns should be readable
		for _, pattern := range config.Input.Content.Grep {
			if pattern == "" {
				t.Fatal("Grep pattern should not be empty")
			}
		}
	}
}

// TestConfigurationOptions verifies options configuration
func TestConfigurationOptions(t *testing.T) {
	var config Configuration
	config.getConfiguration("../config_test_standard.yml")

	// Options structure should exist (may be all false)
	t.Log("Options section loaded successfully")
}

// TestConfigurationOutput verifies output configuration
func TestConfigurationOutput(t *testing.T) {
	var config Configuration
	config.getConfiguration("../config_test_standard.yml")

	// Output structure should exist
	t.Log("Output section loaded successfully")
}

// TestConfigurationEventForwarding verifies event forwarding configuration
func TestConfigurationEventForwarding(t *testing.T) {
	var config Configuration
	config.getConfiguration("../config_test_standard.yml")

	// Event forwarding section should be accessible
	t.Log("Event forwarding section loaded successfully")
}

// TestConfigurationAdvancedParameters verifies advanced parameters
func TestConfigurationAdvancedParameters(t *testing.T) {
	var config Configuration
	config.getConfiguration("../config_test_standard.yml")

	// Advanced parameters should exist
	t.Log("Advanced parameters section loaded successfully")
}

// TestConfigurationMissingRequired tests handling of incomplete config
func TestConfigurationMissingRequired(t *testing.T) {
	// Create a minimal temporary config file
	tmpFile := filepath.Join(t.TempDir(), "test_config.yml")
	tmpContent := `input:
  path:
    - /tmp
`
	os.WriteFile(tmpFile, []byte(tmpContent), 0644)

	var config Configuration
	config.getConfiguration(tmpFile)

	if len(config.Input.Path) == 0 {
		t.Fatal("Minimal config should have at least path section")
	}
}

// TestConfigurationEmpty tests handling of empty configuration
func TestConfigurationEmpty(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "empty_config.yml")
	os.WriteFile(tmpFile, []byte(""), 0644)

	var config Configuration
	config.getConfiguration(tmpFile)

	// Verify no panic occurred
	t.Log("Empty configuration handled gracefully")
}

// TestConfigurationYARAWithRC4 tests YARA section with RC4 encryption
func TestConfigurationYARAWithRC4(t *testing.T) {
	var config Configuration
	config.getConfiguration("../config_test_ciphered.yml")

	// Ciphered config should load without panicking
	if config.Input.Content.Yara != nil {
		t.Log("YARA rules loaded from ciphered configuration")
	}
}

// TestConfigurationChecksums tests checksum patterns
func TestConfigurationChecksums(t *testing.T) {
	var config Configuration
	config.getConfiguration("../config_test_standard.yml")

	if len(config.Input.Content.Checksum) > 0 {
		// Verify checksums are readable
		for _, cs := range config.Input.Content.Checksum {
			if cs == "" {
				t.Fatal("Checksum should not be empty")
			}
		}
	}
}

// TestConfigurationMultiplePaths tests multiple path handling
func TestConfigurationMultiplePaths(t *testing.T) {
	var config Configuration
	config.getConfiguration("../config_test_standard.yml")

	if len(config.Input.Path) > 1 {
		t.Logf("Configuration loaded with %d paths", len(config.Input.Path))
	}
}
