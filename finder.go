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
	"time"

	"github.com/dlclark/regexp2"
	"github.com/h2non/filetype"
	"github.com/h2non/filetype/types"
	"github.com/hillu/go-yara/v4"
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
func FindInFilesContent(files *[]string, patterns []string, rules *yara.Rules, hashList []string, triageMode bool, maxScanFilesize int, cleanMemoryIfFileGreaterThanSize int) *[]string {
	var matchingFiles []string

	InitProgressbar(int64(len(*files)))
	for _, path := range *files {
		ProgressBarStep()
		b, err := ioutil.ReadFile(path)
		if err != nil {
			if triageMode {
				time.Sleep(500 * time.Millisecond)
				b, err = ioutil.ReadFile(path)
				if err != nil {
					LogMessage(LOG_ERROR, "(ERROR)", "Unable to read file", path)
					continue
				}
			} else {
				LogMessage(LOG_ERROR, "(ERROR)", "Unable to read file", path)
				continue
			}

		}

		// cancel analysis if file size is greater than maxScanFilesize
		if len(b) > 1024*1024*maxScanFilesize {
			LogMessage(LOG_ERROR, "(ERROR)", fmt.Sprintf("File %s size is greater than %dMb, skipping", path, maxScanFilesize))
			continue
		}

		// get file type
		filetype, err := filetype.Match(b)
		if err != nil {
			filetype = types.Unknown
		}

		// handle file content and checksum match
		for _, m := range CheckFileChecksumAndContent(path, b, hashList, patterns) {
			if !Contains(matchingFiles, m) {
				LogMessage(LOG_ALERT, "(ALERT)", "File content match on:", path)
				matchingFiles = append(matchingFiles, m)
			}
		}

		// yara scan on file content
		yaraResult, err := PerformYaraScan(&b, rules)
		if err != nil {
			LogMessage(LOG_ERROR, "(ERROR)", "Error performing yara scan on", path, err)
			continue
		}

		if len(yaraResult) > 0 && !Contains(matchingFiles, path) {
			matchingFiles = append(matchingFiles, path)
		}

		// output yara match results
		for i := 0; i < len(yaraResult); i++ {
			LogMessage(LOG_ALERT, "(ALERT)", "YARA match:")
			LogMessage(LOG_ALERT, " | path:", path)
			LogMessage(LOG_ALERT, " | rule namespace:", yaraResult[i].Namespace)
			LogMessage(LOG_ALERT, " | rule name:", yaraResult[i].Rule)
		}

		// if file type is an archive, extract and calculate checksum for every file inside
		if Contains([]string{"application/x-tar", "application/x-7z-compressed", "application/zip", "application/vnd.rar"}, filetype.MIME.Value) {
			zr, err := zip.OpenReader(path)
			if err != nil {
				LogMessage(LOG_ERROR, "(ERROR)", "Cant't open archive file:", path)
				continue
			}

			for _, subFile := range zr.File {
				fr, err := subFile.Open()
				if err != nil {
					LogMessage(LOG_ERROR, "(ERROR)", "Can't open archive file member for reading:", path, subFile.Name)
					continue
				}
				defer fr.Close()

				body, err := ioutil.ReadAll(fr)
				if err != nil {
					LogMessage(LOG_ERROR, "(ERROR)", "Unable to read file archive member:", path, subFile.Name)
					continue
				}

				// handle file content and checksum match for each file in the archive
				for _, m := range CheckFileChecksumAndContent(path, body, hashList, patterns) {
					if !Contains(matchingFiles, m) {
						LogMessage(LOG_ALERT, "(ALERT)", "File content match on:", path)
						matchingFiles = append(matchingFiles, m)
					}
				}

				// yara scan
				yaraResult, err := PerformYaraScan(&body, rules)
				if err != nil {
					LogMessage(LOG_ERROR, "(ERROR)", "Error performing yara scan on", path, err)
				}

				// output yara match results
				for i := 0; i < len(yaraResult); i++ {
					LogMessage(LOG_ALERT, "(ALERT)", "YARA match:")
					LogMessage(LOG_ALERT, " | path:", path, "("+subFile.Name+")")
					LogMessage(LOG_ALERT, " | rule namespace:", yaraResult[i].Namespace)
					LogMessage(LOG_ALERT, " | rule name:", yaraResult[i].Rule)
					for j := 0; j < len(yaraResult[i].Strings); j++ {
						LogMessage(LOG_VERBOSE, " | ", "name:", yaraResult[i].Strings[j].Name, fmt.Sprintf("\"%s\"", yaraResult[i].Strings[j].Data), "offset:", yaraResult[i].Strings[j].Offset)
					}
				}
			}
		}

		// cleaning memory if file size is greater than cleanMemoryIfFileGreaterThanSize
		if len(b) > 1024*1024*cleanMemoryIfFileGreaterThanSize {
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
