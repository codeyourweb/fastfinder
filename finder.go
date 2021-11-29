package main

import (
	"io/ioutil"
	"log"
	"regexp"
	"strings"
)

func pathsFinder(files []string, patterns []string) (matchingFiles []string) {
	for _, expression := range patterns {
		for _, f := range files {
			if match, _ := regexp.MatchString(`(?i)`+expression, f); match {
				matchingFiles = append(matchingFiles, f)
			}
		}
	}

	return matchingFiles
}

func findInFiles(files []string, patterns []string) (matchingFiles []string) {
	for _, f := range files {

		b, err := ioutil.ReadFile(f)
		if err != nil {
			log.Println("Unable to read", f)
			continue
		}

		for _, expression := range patterns {
			if strings.Contains(string(b), expression) {
				if !contains(matchingFiles, f) {
					matchingFiles = append(matchingFiles, f)
				}
			}
		}
	}

	return matchingFiles
}
