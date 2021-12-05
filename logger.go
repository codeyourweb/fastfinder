package main

import (
	"bufio"
	"io"
	"log"
	"os"
)

const (
	LOG_INFO  = 0
	LOG_ERROR = -1
)

// LogMessage output message to the specific standard / error output
func LogMessage(logType int, logMessage ...interface{}) {
	if logType == LOG_INFO {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(os.Stderr)
	}

	log.Println(logMessage...)
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
		LogMessage(LOG_ERROR, "[ERROR]", "Cannot output log to file", err)
	}

	os.Stdout = wr

	go func() {
		scanner := bufio.NewScanner(rd)
		for scanner.Scan() {
			stdoutLine := scanner.Text()
			multiWriter.Write([]byte(stdoutLine + "\r\n"))
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
		LogMessage(LOG_ERROR, "[ERROR]", "Cannot output log to file", err)
	}

	os.Stderr = wr

	go func() {
		scanner := bufio.NewScanner(rd)
		for scanner.Scan() {
			stdoutLine := scanner.Text()
			multiWriter.Write([]byte(stdoutLine + "\r\n"))
		}
	}()
}
