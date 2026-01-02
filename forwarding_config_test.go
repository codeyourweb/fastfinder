package main

import (
	"testing"
)

// TestEventForwardingConfigStructure tests the ForwardingConfig structure
func TestEventForwardingConfigStructure(t *testing.T) {
	config := ForwardingConfig{
		Enabled:    true,
		BufferSize: 256,
		FlushTime:  5,
	}

	if !config.Enabled {
		t.Fatal("Enabled flag not set")
	}

	if config.BufferSize != 256 {
		t.Fatal("BufferSize not set correctly")
	}

	if config.FlushTime != 5 {
		t.Fatal("FlushTime not set correctly")
	}
}

// TestHTTPConfigStructure tests the HTTPConfig structure
func TestHTTPConfigStructure(t *testing.T) {
	config := HTTPConfig{
		Enabled:    true,
		URL:        "http://localhost:8080",
		SSLVerify:  true,
		Timeout:    30,
		RetryCount: 3,
	}

	if !config.Enabled {
		t.Fatal("HTTP Enabled flag not set")
	}

	if config.URL != "http://localhost:8080" {
		t.Fatal("HTTP URL not set correctly")
	}

	if config.Timeout != 30 {
		t.Fatal("HTTP Timeout not set correctly")
	}

	if config.RetryCount != 3 {
		t.Fatal("HTTP RetryCount not set correctly")
	}
}

// TestHTTPConfigHeaders tests HTTP headers handling
func TestHTTPConfigHeaders(t *testing.T) {
	headers := make(map[string]string)
	headers["Content-Type"] = "application/json"
	headers["Authorization"] = "Bearer token123"

	config := HTTPConfig{
		Enabled: true,
		Headers: headers,
	}

	if config.Headers["Content-Type"] != "application/json" {
		t.Fatal("Content-Type header not set")
	}

	if config.Headers["Authorization"] != "Bearer token123" {
		t.Fatal("Authorization header not set")
	}
}

// TestFileOutputConfigStructure tests the FileOutputConfig structure
func TestFileOutputConfigStructure(t *testing.T) {
	config := FileOutputConfig{
		Enabled:       true,
		DirectoryPath: "/var/log/fastfinder",
		RotateMinutes: 60,
		MaxFileSize:   100,
		RetainFiles:   10,
	}

	if !config.Enabled {
		t.Fatal("File output Enabled flag not set")
	}

	if config.DirectoryPath != "/var/log/fastfinder" {
		t.Fatal("Directory path not set correctly")
	}

	if config.RotateMinutes != 60 {
		t.Fatal("Rotate minutes not set correctly")
	}

	if config.MaxFileSize != 100 {
		t.Fatal("Max file size not set correctly")
	}

	if config.RetainFiles != 10 {
		t.Fatal("Retain files count not set correctly")
	}
}

// TestEventFiltersStructure tests the EventFilters structure
func TestEventFiltersStructure(t *testing.T) {
	filters := EventFilters{
		EventTypes:  []string{"alert", "error", "scan_complete"},
		MinSeverity: "medium",
	}

	if len(filters.EventTypes) != 3 {
		t.Fatal("Event types not set correctly")
	}

	if filters.EventTypes[0] != "alert" {
		t.Fatal("First event type incorrect")
	}

	if filters.MinSeverity != "medium" {
		t.Fatal("Min severity not set correctly")
	}
}

// TestForwardingConfigDisabled tests disabled event forwarding
func TestForwardingConfigDisabled(t *testing.T) {
	config := ForwardingConfig{
		Enabled:    false,
		BufferSize: 0,
		FlushTime:  0,
	}

	if config.Enabled {
		t.Fatal("Config should be disabled")
	}
}

// TestForwardingConfigWithHTTP tests forwarding config with HTTP enabled
func TestForwardingConfigWithHTTP(t *testing.T) {
	config := ForwardingConfig{
		Enabled:    true,
		BufferSize: 512,
		FlushTime:  10,
		HTTP: HTTPConfig{
			Enabled: true,
			URL:     "https://collector.example.com/events",
		},
	}

	if !config.Enabled {
		t.Fatal("Main config should be enabled")
	}

	if !config.HTTP.Enabled {
		t.Fatal("HTTP should be enabled")
	}

	if config.HTTP.URL != "https://collector.example.com/events" {
		t.Fatal("HTTP URL not correct")
	}
}

// TestForwardingConfigWithFile tests forwarding config with file output enabled
func TestForwardingConfigWithFile(t *testing.T) {
	config := ForwardingConfig{
		Enabled:    true,
		BufferSize: 256,
		File: FileOutputConfig{
			Enabled:       true,
			DirectoryPath: "/tmp/events",
			RotateMinutes: 30,
		},
	}

	if !config.Enabled {
		t.Fatal("Main config should be enabled")
	}

	if !config.File.Enabled {
		t.Fatal("File output should be enabled")
	}

	if config.File.DirectoryPath != "/tmp/events" {
		t.Fatal("File directory path not correct")
	}
}

// TestForwardingConfigWithFilters tests forwarding config with event filters
func TestForwardingConfigWithFilters(t *testing.T) {
	config := ForwardingConfig{
		Enabled:    true,
		BufferSize: 256,
		Filters: EventFilters{
			EventTypes:  []string{"error", "critical"},
			MinSeverity: "high",
		},
	}

	if len(config.Filters.EventTypes) != 2 {
		t.Fatal("Filters event types not set")
	}

	if config.Filters.MinSeverity != "high" {
		t.Fatal("Filter severity not set")
	}
}

// TestHTTPConfigSSLVerify tests SSL verification flag
func TestHTTPConfigSSLVerify(t *testing.T) {
	configWithSSL := HTTPConfig{
		Enabled:   true,
		SSLVerify: true,
	}

	configWithoutSSL := HTTPConfig{
		Enabled:   true,
		SSLVerify: false,
	}

	if !configWithSSL.SSLVerify {
		t.Fatal("SSL verify should be true")
	}

	if configWithoutSSL.SSLVerify {
		t.Fatal("SSL verify should be false")
	}
}

// TestFileOutputConfigRetention tests file retention settings
func TestFileOutputConfigRetention(t *testing.T) {
	config := FileOutputConfig{
		Enabled:       true,
		DirectoryPath: "/logs",
		RotateMinutes: 1440, // Daily rotation
		MaxFileSize:   500,  // 500 MB
		RetainFiles:   30,   // Keep 30 days
	}

	if config.RotateMinutes != 1440 {
		t.Fatal("Daily rotation not set")
	}

	if config.MaxFileSize != 500 {
		t.Fatal("Max file size not set")
	}

	if config.RetainFiles != 30 {
		t.Fatal("Retention period not set")
	}
}

// TestEventFiltersMultipleTypes tests multiple event types
func TestEventFiltersMultipleTypes(t *testing.T) {
	filters := EventFilters{
		EventTypes: []string{
			"alert",
			"error",
			"warning",
			"info",
			"scan_start",
			"scan_complete",
			"match_found",
		},
		MinSeverity: "low",
	}

	if len(filters.EventTypes) != 7 {
		t.Fatal("Not all event types set")
	}

	found := false
	for _, et := range filters.EventTypes {
		if et == "scan_complete" {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("scan_complete event type not found")
	}
}

// TestForwardingConfigComplex tests complex configuration with both HTTP and File
func TestForwardingConfigComplex(t *testing.T) {
	config := ForwardingConfig{
		Enabled:    true,
		BufferSize: 1024,
		FlushTime:  30,
		HTTP: HTTPConfig{
			Enabled:    true,
			URL:        "https://siem.company.com/ingest",
			SSLVerify:  true,
			Timeout:    60,
			RetryCount: 5,
			Headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer xyz123",
				"X-API-Key":     "secret-key",
			},
		},
		File: FileOutputConfig{
			Enabled:       true,
			DirectoryPath: "/var/log/fastfinder/events",
			RotateMinutes: 60,
			MaxFileSize:   200,
			RetainFiles:   90,
		},
		Filters: EventFilters{
			EventTypes:  []string{"error", "critical", "match_found"},
			MinSeverity: "medium",
		},
	}

	// Verify all components are properly configured
	if !config.Enabled || !config.HTTP.Enabled || !config.File.Enabled {
		t.Fatal("All components should be enabled")
	}

	if len(config.HTTP.Headers) != 3 {
		t.Fatal("HTTP headers not set correctly")
	}

	if len(config.Filters.EventTypes) != 3 {
		t.Fatal("Filter event types not set")
	}
}
