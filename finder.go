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

// PathsFinder try to match regular expressions in file paths slice
func PathsFinder(files *[]string, patterns []*regexp2.Regexp) *[]string {
	InitProgressbar(int64(len(*files)))
	var matchingFiles []string
	for _, expression := range patterns {
		for _, f := range *files {
			ProgressBarStep()
			if match, _ := expression.MatchString(f); match {
				matchingFiles = append(matchingFiles, f)
			}
		}
	}

	return &matchingFiles
}

// FindInFiles check for pattern or checksum match in files slice
func FindInFiles(files *[]string, patterns []string, checksum []string) *[]string {
	var matchingFiles []string
	InitProgressbar(int64(len(*files)))
	for _, f := range *files {
		ProgressBarStep()
		b, err := ioutil.ReadFile(f)
		if err != nil {
			LogMessage(LOG_ERROR, "[ERROR]", "Unable to read file", f)
			continue
		}

		// cancel analysis if file size is greater than 2Gb
		if len(b) > 1024*1024*2048 {
			LogMessage(LOG_ERROR, "[ERROR]", "File size is greater than 2Gb, skipping", f)
			continue
		}

		// if checksum is not empty, calculate md5/sha1/sha256 for every file
		if len(checksum) > 0 {
			var hashs []string
			hashs = append(hashs, fmt.Sprintf("%x", md5.Sum(b)))
			hashs = append(hashs, fmt.Sprintf("%x", sha1.Sum(b)))
			hashs = append(hashs, fmt.Sprintf("%x", sha256.Sum256(b)))

			for _, c := range hashs {
				if Contains(checksum, c) && !Contains(matchingFiles, f) {
					matchingFiles = append(matchingFiles, f)
					LogMessage(LOG_INFO, "[ALERT]", "File match on", f)
				}
			}
		}

		for _, expression := range patterns {
			if strings.Contains(string(b), expression) {
				if !Contains(matchingFiles, f) {
					matchingFiles = append(matchingFiles, f)
					LogMessage(LOG_INFO, "[ALERT]", "File match on", f)
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
