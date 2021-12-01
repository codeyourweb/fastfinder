package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"runtime/debug"
	"strings"

	"github.com/dlclark/regexp2"
)

func pathsFinder(files *[]string, patterns []*regexp2.Regexp) *[]string {
	var matchingFiles []string
	for _, expression := range patterns {
		for _, f := range *files {
			if match, _ := expression.MatchString(f); match {
				matchingFiles = append(matchingFiles, f)
			}
		}
	}

	return &matchingFiles
}

func findInFiles(files *[]string, patterns []string, checksum []string) *[]string {
	var matchingFiles []string
	for _, f := range *files {
		b, err := ioutil.ReadFile(f)
		if err != nil {
			logMessage(LOG_ERROR, "[ERROR]", "Unable to read file", f)
			continue
		}

		// cancel analysis if file size is greater than 2Gb
		if len(b) > 1024*1024*2048 {
			logMessage(LOG_ERROR, "[ERROR]", "File size is greater than 2Gb, skipping", f)
			continue
		}

		// if checksum is not empty, calculate md5/sha1/sha256 for every file
		if len(checksum) > 0 {
			var hashs []string
			hashs = append(hashs, fmt.Sprintf("%x", md5.Sum(b)))
			hashs = append(hashs, fmt.Sprintf("%x", sha1.Sum(b)))
			hashs = append(hashs, fmt.Sprintf("%x", sha256.Sum256(b)))

			for _, c := range hashs {
				if contains(checksum, c) && !contains(matchingFiles, f) {
					matchingFiles = append(matchingFiles, f)
					logMessage(LOG_INFO, "[ALERT]", "File match on", f)
				}
			}
		}

		for _, expression := range patterns {
			if strings.Contains(string(b), expression) {
				if !contains(matchingFiles, f) {
					matchingFiles = append(matchingFiles, f)
					logMessage(LOG_INFO, "[ALERT]", "File match on", f)
				}
			}
		}

		// cleaning memory if file size is greater than 512Mb
		if len(b) > 1024*1024*512 {
			debug.FreeOSMemory()
		}
	}

	return &matchingFiles
}
