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

func logMessage(logType int, logMessage ...interface{}) {
	if logType == LOG_INFO {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(os.Stderr)
	}

	log.Println(logMessage...)
}

func StdoutToLogFile(outLogPath string) {
	f, err := os.OpenFile(outLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	if err != nil {
		logMessage(LOG_ERROR, "Error opening log file: ", err)
		return
	}

	multiWriter := io.MultiWriter(os.Stdout, f)
	rd, wr, err := os.Pipe()
	if err != nil {
		logMessage(LOG_ERROR, "[ERROR]", "Cannot output log to file", err)
	}

	os.Stdout = wr

	go func() {
		scanner := bufio.NewScanner(rd)
		for scanner.Scan() {
			stdoutLine := scanner.Text()
			multiWriter.Write([]byte(stdoutLine + "\n"))
		}
	}()
}

func StderrToLogFile(outLogPath string) {
	f, err := os.OpenFile(outLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	if err != nil {
		logMessage(LOG_ERROR, "Error opening log file: ", err)
		return
	}

	multiWriter := io.MultiWriter(os.Stderr, f)
	rd, wr, err := os.Pipe()
	if err != nil {
		logMessage(LOG_ERROR, "[ERROR]", "Cannot output log to file", err)
	}

	os.Stderr = wr

	go func() {
		scanner := bufio.NewScanner(rd)
		for scanner.Scan() {
			stdoutLine := scanner.Text()
			multiWriter.Write([]byte(stdoutLine + "\n"))
		}
	}()
}
