package main

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/dlclark/regexp2"
	"github.com/hillu/go-yara/v4"
)

// ScannerPipeline manages concurrent file enumeration and scanning
type ScannerPipeline struct {
	fileChan        chan string
	matchesChan     chan string
	errChan         chan error
	wg              sync.WaitGroup
	enumerationDone chan bool
	scanningDone    chan bool
}

// NewScannerPipeline creates a new scanner pipeline
func NewScannerPipeline(bufferSize int) *ScannerPipeline {
	return &ScannerPipeline{
		fileChan:        make(chan string, bufferSize),
		matchesChan:     make(chan string, bufferSize),
		errChan:         make(chan error, bufferSize),
		enumerationDone: make(chan bool, 1),
		scanningDone:    make(chan bool, 1),
	}
}

// StartEnumeration starts a goroutine that enumerates files and sends them through the channel
func (sp *ScannerPipeline) StartEnumeration(paths []string, excludedPaths []string) {
	sp.wg.Add(1)
	go func() {
		defer sp.wg.Done()
		for _, path := range paths {
			enumerateFilesStreaming(path, excludedPaths, sp.fileChan)
		}
		close(sp.fileChan)
		sp.enumerationDone <- true
	}()
}

// StartScanning starts a goroutine that scans files received from the channel
func (sp *ScannerPipeline) StartScanning(
	patterns []string,
	rules *yara.Rules,
	hashList []string,
	maxScanFilesize int,
	cleanMemoryIfFileGreaterThanSize int,
	pathPatterns []*regexp2.Regexp,
	contentDependsOnPath bool) {

	sp.wg.Add(1)
	go func() {
		defer sp.wg.Done()
		sp.scanFiles(patterns, rules, hashList, maxScanFilesize, cleanMemoryIfFileGreaterThanSize, pathPatterns, contentDependsOnPath)
		sp.scanningDone <- true
	}()
}

// StartScanningPathOnly scans only path patterns without content scanning
func (sp *ScannerPipeline) StartScanningPathOnly(pathPatterns []*regexp2.Regexp) {
	sp.wg.Add(1)
	go func() {
		defer sp.wg.Done()
		sp.scanFilesPathOnly(pathPatterns)
		sp.scanningDone <- true
	}()
}

// GetMatches returns matches as they are found
func (sp *ScannerPipeline) GetMatches() <-chan string {
	return sp.matchesChan
}

// GetErrors returns errors as they occur
func (sp *ScannerPipeline) GetErrors() <-chan error {
	return sp.errChan
}

// Wait waits for enumeration to complete
func (sp *ScannerPipeline) WaitEnumeration() {
	<-sp.enumerationDone
}

// Wait waits for scanning to complete
func (sp *ScannerPipeline) WaitScanning() {
	<-sp.scanningDone
}

// WaitAll waits for both enumeration and scanning to complete
func (sp *ScannerPipeline) WaitAll() {
	sp.wg.Wait()
	close(sp.matchesChan)
	close(sp.errChan)
}

// enumerateFilesStreaming enumerates files and sends them through a channel using parallel workers
func enumerateFilesStreaming(path string, excludedPaths []string, fileChan chan string) {
	const numWorkers = 8 // Number of parallel workers for directory enumeration

	dirQueue := make(chan string, 1000) // Queue of directories to process
	var wg sync.WaitGroup
	var dirCountMutex sync.Mutex
	dirCount := int64(0)

	// Launch worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dirPath := range dirQueue {
				enumerateDirectoryWorker(dirPath, excludedPaths, fileChan, dirQueue, &wg, &dirCount, &dirCountMutex)
			}
		}()
	}

	// Queue the root directory
	wg.Add(1)
	dirQueue <- path

	// Wait for all workers to finish
	wg.Wait()
	close(dirQueue)
}

// enumerateDirectoryWorker processes a single directory and queues its subdirectories
func enumerateDirectoryWorker(dirPath string, excludedPaths []string, fileChan chan string, dirQueue chan string, wg *sync.WaitGroup, dirCount *int64, mutex *sync.Mutex) {
	// Update directory count
	mutex.Lock()
	*dirCount++
	mutex.Unlock()

	// Log directory in verbose mode
	LogMessage(LOG_VERBOSE, "(ENUM)", "Enumerating directory:", dirPath)

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		LogMessage(LOG_ERROR, "(ERROR)", err)
		return
	}

	// Process all entries in this directory
	for _, entry := range entries {
		fullPath := filepath.Join(dirPath, entry.Name())

		// Check if path is excluded
		isExcluded := false
		for _, excludedPath := range excludedPaths {
			if len(excludedPath) > 1 && strings.HasPrefix(fullPath, excludedPath) && len(fullPath) > len(excludedPath) {
				isExcluded = true
				break
			}
		}

		if isExcluded {
			continue
		}

		if entry.IsDir() {
			// Queue subdirectory for processing by a worker
			wg.Add(1)
			dirQueue <- fullPath
		} else {
			// Send file to the channel
			fileChan <- fullPath
		}
	}
}

// scanFiles scans files received from the channel
func (sp *ScannerPipeline) scanFiles(
	patterns []string,
	rules *yara.Rules,
	hashList []string,
	maxScanFilesize int,
	cleanMemoryIfFileGreaterThanSize int,
	pathPatterns []*regexp2.Regexp,
	contentDependsOnPath bool) {

	for filePath := range sp.fileChan {
		// Check path patterns first if they exist
		if len(pathPatterns) > 0 {
			pathMatches := false
			for _, pattern := range pathPatterns {
				if match, _ := pattern.MatchString(filePath); match {
					pathMatches = true
					break
				}
			}

			// If content depends on path match and path didn't match, skip
			if contentDependsOnPath && !pathMatches {
				continue
			}

			// If content doesn't depend on path match, send path match
			if !contentDependsOnPath && pathMatches {
				LogMessage(LOG_ALERT, "(ALERT)", "File path match on:", filePath)
				sp.matchesChan <- filePath
			}
		}

		// Scan file content if criteria exist
		if len(patterns) > 0 || len(hashList) > 0 || (rules != nil && len(rules.GetRules()) > 0) {
			b, err := os.ReadFile(filePath)
			if err != nil {
				LogMessage(LOG_ERROR, "(ERROR)", "Unable to read file", filePath)
				continue
			}

			// Check file size
			if len(b) > 1024*1024*maxScanFilesize {
				LogMessage(LOG_WARNING, "(WARNING)", "File size exceeds limit, skipping:", filePath)
				continue
			}

			// Check checksum and grep patterns
			for _, m := range CheckFileChecksumAndContent(filePath, b, hashList, patterns) {
				LogMessage(LOG_ALERT, "(ALERT)", "File content match on:", filePath)
				sp.matchesChan <- m
			}

			// YARA scan
			if rules != nil && len(rules.GetRules()) > 0 {
				LogMessage(LOG_VERBOSE, "(YARA)", "Scanning file with YARA rules:", filePath)
				yaraResult, err := PerformYaraScan(&b, rules)
				if err != nil {
					LogMessage(LOG_ERROR, "(ERROR)", "Error performing yara scan on", filePath, err)
					continue
				}

				if len(yaraResult) > 0 {
					sp.matchesChan <- filePath

					for i := 0; i < len(yaraResult); i++ {
						message := "YARA match | path: " + filePath + " | rule namespace: " + yaraResult[i].Namespace + " | rule name: " + yaraResult[i].Rule
						LogMessage(LOG_ALERT, "(ALERT)", message)
					}
				}
			}

			// Clean memory if file was large
			if len(b) > 1024*1024*cleanMemoryIfFileGreaterThanSize {
				debug.FreeOSMemory()
			}
		}
	}
}

// scanFilesPathOnly scans only path patterns
func (sp *ScannerPipeline) scanFilesPathOnly(pathPatterns []*regexp2.Regexp) {
	for filePath := range sp.fileChan {
		for _, pattern := range pathPatterns {
			if match, _ := pattern.MatchString(filePath); match {
				LogMessage(LOG_ALERT, "(ALERT)", "File path match on:", filePath)
				sp.matchesChan <- filePath
				break
			}
		}
	}
}

// CollectMatches collects all matches from the pipeline
func (sp *ScannerPipeline) CollectMatches() []string {
	var matches []string
	for match := range sp.matchesChan {
		matches = append(matches, match)
	}
	return matches
}
