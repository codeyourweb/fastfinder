package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const (
	LOG_EXIT    = 0
	LOG_ALERT   = 1 // Most important (alerts only)
	LOG_WARNING = 2 // Warnings and alerts
	LOG_ERROR   = 3 // Errors, warnings and alerts
	LOG_INFO    = 4 // Info, errors, warnings and alerts
	LOG_VERBOSE = 5 // Full verbosity (all messages)
)

var loggingVerbosity int = 3
var loggingPath string = ""
var loggingFile *os.File
var unitTesting bool
var guiLogOutput func(logType int, prefix string, message ...interface{})

func LogTesting(testing bool) {
	unitTesting = testing

	if !testing {
		log.SetOutput(os.Stderr)
	}
}

// LogMessage output message to the specific standard / error output
func LogMessage(logType int, logMessage ...interface{}) {
	aString := make([]string, len(logMessage))
	for i, v := range logMessage {
		aString[i] = fmt.Sprintf("%v", v)
	}

	message := strings.Join(aString, " ")

	// Forward events based on log type
	switch logType {
	case LOG_ALERT:
		ForwardEvent("alert", "high", message, nil)
	case LOG_WARNING:
		ForwardEvent("warning", "low", message, nil)
	case LOG_ERROR:
		ForwardEvent("error", "medium", message, nil)
	case LOG_INFO:
		ForwardEvent("info", "low", message, nil)
	}

	// Check if GUI mode is active (Gio)
	if guiLogOutput != nil {
		currentTime := time.Now().UTC()
		timestampedMessage := "[" + currentTime.Format("2006-01-02 15:04:05") + " UTC] " + message
		guiLogOutput(logType, "", timestampedMessage)
	} else if UIactive && AppStarted && !unitTesting {
		// Console tview mode - apply verbosity filtering
		shouldDisplay := false
		switch logType {
		case LOG_ALERT:
			shouldDisplay = (loggingVerbosity >= 1)
		case LOG_WARNING:
			shouldDisplay = (loggingVerbosity >= 2)
		case LOG_ERROR:
			shouldDisplay = (loggingVerbosity >= 3)
		case LOG_INFO:
			shouldDisplay = (loggingVerbosity >= 4)
		case LOG_VERBOSE:
			shouldDisplay = (loggingVerbosity >= 5)
		case LOG_EXIT:
			shouldDisplay = true
		}

		if shouldDisplay {
			currentTime := time.Now().UTC()
			message = "[" + currentTime.Format("2006-01-02 15:04:05") + " UTC] " + message
			if logType == LOG_INFO || logType == LOG_VERBOSE || logType == LOG_EXIT {
				txtStdout.ScrollToEnd()
				fmt.Fprintf(txtStdout, "%s\n", message)
			} else if logType == LOG_ALERT {
				txtMatchs.ScrollToEnd()
				fmt.Fprintf(txtMatchs, "%s\n", message)
			} else {
				txtStderr.ScrollToEnd()
				fmt.Fprintf(txtStderr, "%s\n", message)
			}
		}
	} else {
		// Pure console mode - check verbosity for console output
		// New verbosity: 1=alerts only, 2=alerts+warnings, 3=alerts+warnings+errors, 4=alerts+warnings+errors+info, 5=full
		shouldDisplay := false
		switch logType {
		case LOG_ALERT:
			shouldDisplay = (loggingVerbosity >= 1) // Display if verbosity 1 or higher
		case LOG_WARNING:
			shouldDisplay = (loggingVerbosity >= 2) // Display if verbosity 2 or higher
		case LOG_ERROR:
			shouldDisplay = (loggingVerbosity >= 3) // Display if verbosity 3 or higher
		case LOG_INFO:
			shouldDisplay = (loggingVerbosity >= 4) // Display if verbosity 4 or higher
		case LOG_VERBOSE:
			shouldDisplay = (loggingVerbosity >= 5) // Display if verbosity 5 (full)
		case LOG_EXIT:
			shouldDisplay = true // Always display exit messages
		}

		if shouldDisplay && !unitTesting {
			if logType == LOG_ERROR {
				log.SetOutput(os.Stderr)
			} else {
				log.SetOutput(os.Stdout)
			}
			log.Println(message)
		}
	}

	if len(loggingPath) > 0 {
		LogToFile(logType, message)
	}
}

// LogFatal use LogMessage and exit program
func LogFatal(message string) {
	LogMessage(LOG_ERROR, message)
	ExitProgram(1, !UIactive)
}

// LogToFile copy output log flow to the specified file according to the desired loglevel
func LogToFile(logType int, message string) {
	var err error
	if loggingFile == nil {
		loggingFile, err = os.OpenFile(loggingPath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			loggingPath = ""
			LogMessage(LOG_ERROR, "(ERROR)", "Unable to write log file")
			ExitProgram(1, !UIactive)
		}
	}

	// New verbosity logic: lower numbers = higher importance
	// logType 1 (ALERT) should be logged at verbosity 1,2,3,4
	// logType 2 (ERROR) should be logged at verbosity 2,3,4
	// logType 3 (INFO) should be logged at verbosity 3,4
	// logType 4 (VERBOSE) should be logged at verbosity 4
	if logType == LOG_EXIT || logType <= loggingVerbosity {
		if _, err := loggingFile.WriteString(message + "\n"); err != nil {
			loggingPath = ""
			LogMessage(LOG_ERROR, "(ERROR)", "Unable to write log file")
			ExitProgram(1, !UIactive)
		}
	}

}
