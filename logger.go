package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

const (
	LOG_VERBOSE = 0
	LOG_EXIT    = 1
	LOG_ERROR   = 2
	LOG_INFO    = 3
	LOG_ALERT   = 4
)

// LogMessage output message to the specific standard / error output
func LogMessage(logType int, logMessage ...interface{}) {
	aString := make([]string, len(logMessage))
	for i, v := range logMessage {
		aString[i] = fmt.Sprintf("%v", v)
	}
	currentTime := time.Now()

	message := "[" + currentTime.Format("2006-01-02 15:04:05") + "] " + strings.Join(aString, " ")

	if UIactive {
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
}

// StdoutToLogFile copy the standard output flow to the specified file
func StdoutToLogFile(outLogPath string) {
	f, err := os.OpenFile(outLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	if err != nil {
		LogMessage(LOG_ERROR, "Error opening log file: ", err)
		return
	}

	multiWriter := io.MultiWriter(os.Stdout, f)
	rd, wr, err := os.Pipe()
	if err != nil {
		LogMessage(LOG_ERROR, "{ERROR}", "Cannot output log to file", err)
	}

	os.Stdout = wr

	go func() {
		scanner := bufio.NewScanner(rd)
		for scanner.Scan() {
			stdoutLine := scanner.Text()
			multiWriter.Write([]byte(stdoutLine + LineBreak))
		}
	}()
}

// StderrToLogFile copy the standard error flow to the specified file
func StderrToLogFile(outLogPath string) {
	f, err := os.OpenFile(outLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	if err != nil {
		LogMessage(LOG_ERROR, "Error opening log file: ", err)
		return
	}

	multiWriter := io.MultiWriter(os.Stderr, f)
	rd, wr, err := os.Pipe()
	if err != nil {
		LogMessage(LOG_ERROR, "{ERROR}", "Cannot output log to file", err)
	}

	os.Stderr = wr

	go func() {
		scanner := bufio.NewScanner(rd)
		for scanner.Scan() {
			stdoutLine := scanner.Text()
			multiWriter.Write([]byte(stdoutLine + LineBreak))
		}
	}()
}
