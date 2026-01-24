package main

import (
	"fmt"
	"runtime/debug"

	"github.com/hillu/go-yara/v4"
)

// ProcessInformation wrap basic process information and memory dump in a structure
type ProcessInformation struct {
	PID         uint32
	ProcessName string
	ProcessPath string
	MemoryDump  []byte
}

// ScanMemory enumerates processes and scans their memory
func ScanMemory(config Configuration, rules *yara.Rules) {
	LogMessage(LOG_INFO, "(INIT)", "Starting memory scan...")

	procs := ListProcesses()
	LogMessage(LOG_INFO, "(INFO)", fmt.Sprintf("Found %d running processes", len(procs)))

	ScanProcesses(procs, config, rules)

	LogMessage(LOG_INFO, "(INFO)", "Memory scan finished")
}

// ScanProcesses scans a list of processes for patterns and YARA rules
func ScanProcesses(procs []ProcessInformation, config Configuration, rules *yara.Rules) int {
	totalMatches := 0
	for _, proc := range procs {
		LogMessage(LOG_VERBOSE, "(MEMORY)", "Scanning process:", proc.ProcessName, fmt.Sprintf("(PID: %d)", proc.PID))

		// Check memory content with Grep
		if len(config.Input.Content.Grep) > 0 {
			// checkForStringPattern already handles logging and alerting
			matches := checkForStringPattern(fmt.Sprintf("MEMORY:%s:%d", proc.ProcessName, proc.PID), proc.MemoryDump, config.Input.Content.Grep)
			totalMatches += len(matches)
		}

		// Check memory content with YARA
		if rules != nil && len(rules.GetRules()) > 0 {
			matchs, err := PerformYaraScan(&proc.MemoryDump, rules)
			if err != nil {
				LogMessage(LOG_ERROR, "(ERROR)", "Memory YARA scan failed for", proc.ProcessName, err)
			} else {
				totalMatches += len(matchs)
			}

			for i := 0; i < len(matchs); i++ {
				LogMessage(LOG_ALERT, "(ALERT)", "Memory YARA match:")
				LogMessage(LOG_ALERT, " | process:", proc.ProcessName)
				LogMessage(LOG_ALERT, " | PID:", fmt.Sprintf("%d", proc.PID))
				LogMessage(LOG_ALERT, " | rule:", matchs[i].Rule)
				LogMessage(LOG_ALERT, " | namespace:", matchs[i].Namespace)

				// Forward alert
				metadata := map[string]string{
					"pid":            fmt.Sprintf("%d", proc.PID),
					"process_name":   proc.ProcessName,
					"rule_namespace": matchs[i].Namespace,
				}
				ForwardAlertEvent(matchs[i].Rule, "memory:"+proc.ProcessName, int64(len(proc.MemoryDump)), "", metadata)
			}
		}

		// Clean memory
		proc.MemoryDump = nil
		debug.FreeOSMemory()
	}
	return totalMatches
}
