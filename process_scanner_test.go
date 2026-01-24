package main

import (
	"testing"

	"github.com/hillu/go-yara/v4"
)

func TestScanProcessesGrep(t *testing.T) {
	// Setup
	config := Configuration{}
	config.Input.Content.Grep = []string{"bad_string"}

	proc := ProcessInformation{
		PID:         1234,
		ProcessName: "test_process.exe",
		MemoryDump:  []byte("This is a memory dump containing a bad_string here."),
	}
	procs := []ProcessInformation{proc}

	// Execute
	matches := ScanProcesses(procs, config, nil)

	// Verify
	if matches != 1 {
		t.Errorf("Expected 1 match, got %d", matches)
	}
}

func TestScanProcessesNoMatch(t *testing.T) {
	// Setup
	config := Configuration{}
	config.Input.Content.Grep = []string{"missing_string"}

	proc := ProcessInformation{
		PID:         1234,
		ProcessName: "test_process.exe",
		MemoryDump:  []byte("This is a memory dump containing a bad_string here."),
	}
	procs := []ProcessInformation{proc}

	// Execute
	matches := ScanProcesses(procs, config, nil)

	// Verify
	if matches != 0 {
		t.Errorf("Expected 0 matches, got %d", matches)
	}
}

func TestScanProcessesYara(t *testing.T) {
	c, err := yara.NewCompiler()
	if err != nil {
		t.Skip("YARA compiler not available: ", err)
		return
	}
	err = c.AddString(`rule test { strings: $a = "yara_match" condition: $a }`, "test")
	if err != nil {
		t.Fatal("Failed to compile yara rule:", err)
	}
	rules, err := c.GetRules()
	if err != nil {
		t.Fatal("Failed to get rules:", err)
	}

	config := Configuration{}
	proc := ProcessInformation{
		PID:         1234,
		ProcessName: "test_process.exe",
		MemoryDump:  []byte("Before yara_match After"),
	}

	matches := ScanProcesses([]ProcessInformation{proc}, config, rules)
	if matches != 1 {
		t.Errorf("Expected 1 YARA match, got %d", matches)
	}
}
