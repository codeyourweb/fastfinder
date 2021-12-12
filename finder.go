package main

import (
	"archive/zip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"runtime/debug"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/h2non/filetype"
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
func FindInFiles(files *[]string, patterns []string, hashList []string) *[]string {
	var matchingFiles []string
	InitProgressbar(int64(len(*files)))
	for _, path := range *files {
		ProgressBarStep()
		b, err := ioutil.ReadFile(path)
		if err != nil {
			LogMessage(LOG_ERROR, "[ERROR]", "Unable to read file", path)
			continue
		}

		// cancel analysis if file size is greater than 2Gb
		if len(b) > 1024*1024*2048 {
			LogMessage(LOG_ERROR, "[ERROR]", "File size is greater than 2Gb, skipping", path)
			continue
		}

		// get file type
		filetype, err := filetype.Match(b)
		if err != nil {
			LogMessage(LOG_ERROR, "[ERROR]", "Unable to get file type", path)
		}

		for _, m := range CheckFileChecksumAndContent(path, b, hashList, patterns) {
			if !Contains(matchingFiles, m) {
				LogMessage(LOG_INFO, "[ALERT]", "File match on", path)
				matchingFiles = append(matchingFiles, m)
			}
		}

		// if file type is an archive, extract and calculate checksum for every file inside
		if Contains([]string{"application/x-tar", "application/x-7z-compressed", "application/zip", "application/vnd.rar"}, filetype.MIME.Value) {
			zr, err := zip.OpenReader(path)
			if err != nil {
				fmt.Printf("cant't open archive file: %s: %v\n", path, err)
				continue
			}

			for _, subFile := range zr.File {
				fr, err := subFile.Open()
				if err != nil {
					fmt.Printf("can't open archive file member for reading: %s (%s): %v\n", path, subFile.Name, err)
					continue
				}
				defer fr.Close()

				body, err := ioutil.ReadAll(fr)
				if err != nil {
					LogMessage(LOG_ERROR, "[ERROR]", "Unable to read file archive member: %s (%s): %v\n", path, subFile.Name, err)
					continue
				}

				for _, m := range CheckFileChecksumAndContent(path, body, hashList, patterns) {
					if !Contains(matchingFiles, m) {
						LogMessage(LOG_INFO, "[ALERT]", "File match on", path)
						matchingFiles = append(matchingFiles, m)
					}
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

// CheckFileChecksumAndContent check for pattern or checksum match in files slice
func CheckFileChecksumAndContent(path string, content []byte, hashList []string, patterns []string) (matchingFiles []string) {
	// compare file checksum with hashList
	if len(hashList) > 0 {
		matchingFiles = append(matchingFiles, checkForChecksum(path, content, hashList)...)
	}

	// compare file content with patterns
	if len(patterns) > 0 {
		matchingFiles = append(matchingFiles, checkForStringPattern(path, content, patterns)...)
	}

	return matchingFiles
}

// checkForChecksum calculate content checksum and check if it is in hashlist
func checkForChecksum(path string, content []byte, hashList []string) (matchingFiles []string) {
	var hashs []string
	hashs = append(hashs, fmt.Sprintf("%x", md5.Sum(content)))
	hashs = append(hashs, fmt.Sprintf("%x", sha1.Sum(content)))
	hashs = append(hashs, fmt.Sprintf("%x", sha256.Sum256(content)))

	for _, c := range hashs {
		if Contains(hashList, c) && !Contains(matchingFiles, path) {
			matchingFiles = append(matchingFiles, path)
		}
	}

	return matchingFiles
}

// checkForStringPattern check if file content matches any specified pattern
func checkForStringPattern(path string, content []byte, patterns []string) (matchingFiles []string) {
	for _, expression := range patterns {
		if strings.Contains(string(content), expression) {
			matchingFiles = append(matchingFiles, path)
		}
	}
	return matchingFiles
}
