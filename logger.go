package main

import (
	"log"
	"os"
)

const LOG_INFO = 0
const LOG_ERROR = -1

func logMessage(logType int, logMessage ...interface{}) {
	if logType == LOG_INFO {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(os.Stderr)
	}

	log.Println(logMessage...)
}
