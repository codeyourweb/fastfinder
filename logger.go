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
	LOG_VERBOSE = 1
	LOG_INFO    = 2
	LOG_ERROR   = 3
	LOG_ALERT   = 4
)

var loggingVerbosity int = 3
var loggingPath string = ""
var loggingFile *os.File

// LogMessage output message to the specific standard / error output
func LogMessage(logType int, logMessage ...interface{}) {
	aString := make([]string, len(logMessage))
	for i, v := range logMessage {
		aString[i] = fmt.Sprintf("%v", v)
	}

	message := strings.Join(aString, " ")

	if UIactive {
		currentTime := time.Now()
		message = "[" + currentTime.Format("2006-01-02 15:04:05") + "] " + message
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
	} else {
		if logType == LOG_ERROR {
			log.SetOutput(os.Stderr)
		} else {
			log.SetOutput(os.Stdout)
		}

		log.Println(message)
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

	if logType == LOG_EXIT || logType >= loggingVerbosity {
		if _, err := loggingFile.WriteString(message + "\n"); err != nil {
			loggingPath = ""
			LogMessage(LOG_ERROR, "(ERROR)", "Unable to write log file")
			ExitProgram(1, !UIactive)
		}
	}

}
