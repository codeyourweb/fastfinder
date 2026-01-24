package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// EventForwarder handles forwarding of events to external endpoints
type EventForwarder struct {
	config          *ForwardingConfig
	eventQueue      []FastFinderEvent
	queueMutex      sync.Mutex
	stopChannel     chan bool
	httpClient      *http.Client
	currentFile     *os.File
	currentFilePath string
	lastRotation    time.Time
	fileMutex       sync.Mutex
	wg              sync.WaitGroup
}

// FastFinderEvent represents an event to be forwarded
type FastFinderEvent struct {
	Timestamp   string            `json:"timestamp"`
	Hostname    string            `json:"hostname"`
	EventType   string            `json:"event_type"` // "alert", "error", "info", "scan_start", "scan_complete"
	Severity    string            `json:"severity"`   // "low", "medium", "high", "critical"
	Message     string            `json:"message"`
	FilePath    string            `json:"file_path,omitempty"`
	RuleName    string            `json:"rule_name,omitempty"`
	FileSize    int64             `json:"file_size,omitempty"`
	FileHash    string            `json:"file_hash,omitempty"`
	ConfigPath  string            `json:"config_path,omitempty"`
	ScanResults *ScanResultsEvent `json:"scan_results,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ScanResultsEvent contains scan completion statistics
type ScanResultsEvent struct {
	FilesScanned    int `json:"files_scanned"`
	MatchesFound    int `json:"matches_found"`
	ErrorsEncounted int `json:"errors_encountered"`
	ScanDuration    int `json:"scan_duration_seconds"`
}

// ForwardingConfig represents the configuration for event forwarding
type ForwardingConfig struct {
	Enabled    bool             `yaml:"enabled"`
	BufferSize int              `yaml:"buffer_size"`
	FlushTime  int              `yaml:"flush_time_seconds"`
	HTTP       HTTPConfig       `yaml:"http"`
	File       FileOutputConfig `yaml:"file"`
	Filters    EventFilters     `yaml:"filters"`
}

// HTTPConfig represents HTTP forwarding configuration
type HTTPConfig struct {
	Enabled    bool              `yaml:"enabled"`
	URL        string            `yaml:"url"`
	SSLVerify  bool              `yaml:"ssl_verify"`
	Timeout    int               `yaml:"timeout_seconds"`
	Headers    map[string]string `yaml:"headers"`
	RetryCount int               `yaml:"retry_count"`
}

// FileOutputConfig represents file output configuration
type FileOutputConfig struct {
	Enabled       bool   `yaml:"enabled"`
	DirectoryPath string `yaml:"directory_path"`   // Directory where log files will be stored
	RotateMinutes int    `yaml:"rotate_minutes"`   // Log rotation interval in minutes
	MaxFileSize   int    `yaml:"max_file_size_mb"` // Maximum file size before rotation (MB)
	RetainFiles   int    `yaml:"retain_files"`     // Number of old log files to retain
}

// EventFilters represents filtering configuration for events
type EventFilters struct {
	EventTypes []string `yaml:"event_types"` // ["alert", "error", "info", "scan_start", "scan_complete"]
}

// Global event forwarder instance
var eventForwarder *EventForwarder

// InitializeEventForwarding initializes the event forwarding system
func InitializeEventForwarding(config *ForwardingConfig) error {
	if config == nil || !config.Enabled {
		return nil
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	// Create HTTP client with appropriate settings
	httpClient := &http.Client{
		Timeout: time.Duration(config.HTTP.Timeout) * time.Second,
	}

	// Set default values if not specified
	if config.BufferSize <= 0 {
		config.BufferSize = 100
	}
	if config.FlushTime <= 0 {
		config.FlushTime = 10 // Default to 10 seconds
	}
	if config.File.DirectoryPath == "" {
		config.File.DirectoryPath = "./logs" // Default log directory
	}
	if config.File.RotateMinutes <= 0 {
		config.File.RotateMinutes = 60 // Default to 1 hour
	}
	if config.File.RetainFiles <= 0 {
		config.File.RetainFiles = 10 // Default to keep 10 old files
	}

	if !config.HTTP.SSLVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	eventForwarder = &EventForwarder{
		config:      config,
		eventQueue:  make([]FastFinderEvent, 0, config.BufferSize),
		stopChannel: make(chan bool),
		httpClient:  httpClient,
	}

	eventForwarder.wg.Add(1)
	// Start the forwarding goroutine
	go eventForwarder.forwardingLoop()

	LogMessage(LOG_INFO, "Event forwarding initialized successfully")
	return nil
}

// ForwardEvent queues an event for forwarding
func ForwardEvent(eventType, severity, message string, metadata map[string]string) {
	if eventForwarder == nil || !eventForwarder.config.Enabled {
		return
	}

	// Apply filters
	if !eventForwarder.shouldForwardEvent(eventType, severity) {
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	event := FastFinderEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Hostname:  hostname,
		EventType: eventType,
		Severity:  severity,
		Message:   message,
		Metadata:  metadata,
	}

	eventForwarder.queueMutex.Lock()
	eventForwarder.eventQueue = append(eventForwarder.eventQueue, event)

	// Auto-flush if buffer is full
	if len(eventForwarder.eventQueue) >= eventForwarder.config.BufferSize {
		go eventForwarder.flushEvents()
	}
	eventForwarder.queueMutex.Unlock()
}

// ForwardAlertEvent forwards a YARA rule match event
func ForwardAlertEvent(ruleName, filePath string, fileSize int64, fileHash string, metadata map[string]string) {
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["rule_name"] = ruleName
	metadata["file_path"] = filePath
	metadata["file_size"] = fmt.Sprintf("%d", fileSize)
	if fileHash != "" {
		metadata["file_hash"] = fileHash
	}

	ForwardEvent("alert", "high", fmt.Sprintf("YARA rule match: %s in %s", ruleName, filePath), metadata)
}

// ForwardScanCompleteEvent forwards scan completion statistics
func ForwardScanCompleteEvent(filesScanned, matchesFound, errorsEncountered int, duration time.Duration) {
	if eventForwarder == nil {
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	scanResults := &ScanResultsEvent{
		FilesScanned:    filesScanned,
		MatchesFound:    matchesFound,
		ErrorsEncounted: errorsEncountered,
		ScanDuration:    int(duration.Seconds()),
	}

	event := FastFinderEvent{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		Hostname:    hostname,
		EventType:   "scan_complete",
		Severity:    "info",
		Message:     fmt.Sprintf("Scan completed: %d files scanned, %d matches found", filesScanned, matchesFound),
		ScanResults: scanResults,
	}

	eventForwarder.queueMutex.Lock()
	eventForwarder.eventQueue = append(eventForwarder.eventQueue, event)
	eventForwarder.queueMutex.Unlock()
}

// shouldForwardEvent checks if an event should be forwarded based on filters
func (ef *EventForwarder) shouldForwardEvent(eventType, severity string) bool {
	// Check event type filter
	if len(ef.config.Filters.EventTypes) > 0 {
		found := false
		for _, allowedType := range ef.config.Filters.EventTypes {
			if allowedType == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// forwardingLoop runs the periodic event forwarding
func (ef *EventForwarder) forwardingLoop() {
	defer ef.wg.Done()
	ticker := time.NewTicker(time.Duration(ef.config.FlushTime) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ef.flushEvents()
		case <-ef.stopChannel:
			ef.flushEvents() // Final flush before stopping
			return
		}
	}
}

// flushEvents sends queued events to configured endpoints
func (ef *EventForwarder) flushEvents() {
	ef.queueMutex.Lock()
	if len(ef.eventQueue) == 0 {
		ef.queueMutex.Unlock()
		return
	}

	eventsToSend := make([]FastFinderEvent, len(ef.eventQueue))
	copy(eventsToSend, ef.eventQueue)
	ef.eventQueue = ef.eventQueue[:0] // Clear the queue
	ef.queueMutex.Unlock()

	// Send to HTTP endpoint if configured
	if ef.config.HTTP.Enabled && ef.config.HTTP.URL != "" {
		ef.sendToHTTP(eventsToSend)
	}

	// Write to file if configured
	if ef.config.File.Enabled && ef.config.File.DirectoryPath != "" {
		ef.writeToFile(eventsToSend)
	}
}

// sendToHTTP sends events to HTTP endpoint
func (ef *EventForwarder) sendToHTTP(events []FastFinderEvent) {
	jsonData, err := json.Marshal(events)
	if err != nil {
		LogMessage(LOG_ERROR, "Failed to marshal events to JSON:", err)
		return
	}

	// Retry logic
	for attempt := 0; attempt <= ef.config.HTTP.RetryCount; attempt++ {
		req, err := http.NewRequest("POST", ef.config.HTTP.URL, bytes.NewBuffer(jsonData))
		if err != nil {
			LogMessage(LOG_ERROR, "Failed to create HTTP request:", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "FastFinder/"+FASTFINDER_VERSION)

		// Add custom headers
		for key, value := range ef.config.HTTP.Headers {
			req.Header.Set(key, value)
		}

		resp, err := ef.httpClient.Do(req)
		if err != nil {
			if attempt < ef.config.HTTP.RetryCount {
				LogMessage(LOG_ERROR, fmt.Sprintf("HTTP forwarding failed (attempt %d/%d): %v", attempt+1, ef.config.HTTP.RetryCount+1, err))
				time.Sleep(time.Second * time.Duration(attempt+1)) // Exponential backoff
				continue
			} else {
				LogMessage(LOG_ERROR, "HTTP forwarding failed after all retries:", err)
				return
			}
		}

		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			LogMessage(LOG_VERBOSE, fmt.Sprintf("Successfully forwarded %d events to %s", len(events), ef.config.HTTP.URL))
			return
		} else if attempt < ef.config.HTTP.RetryCount {
			LogMessage(LOG_ERROR, fmt.Sprintf("HTTP forwarding received status %d (attempt %d/%d)", resp.StatusCode, attempt+1, ef.config.HTTP.RetryCount+1))
			time.Sleep(time.Second * time.Duration(attempt+1))
			continue
		} else {
			LogMessage(LOG_ERROR, fmt.Sprintf("HTTP forwarding failed with status %d after all retries", resp.StatusCode))
			return
		}
	}
}

// writeToFile writes events to the configured file with rotation support
func (ef *EventForwarder) writeToFile(events []FastFinderEvent) {
	if !ef.config.File.Enabled {
		return
	}

	ef.fileMutex.Lock()
	defer ef.fileMutex.Unlock()

	// Check if rotation is needed
	if err := ef.checkAndRotateFile(); err != nil {
		LogMessage(LOG_ERROR, "Failed to rotate file:", err)
		return
	}

	// Ensure current file is open
	if ef.currentFile == nil {
		if err := ef.openNewFile(); err != nil {
			LogMessage(LOG_ERROR, "Failed to open new file:", err)
			return
		}
	}

	for _, event := range events {
		jsonData, err := json.Marshal(event)
		if err != nil {
			LogMessage(LOG_ERROR, "Failed to marshal event to JSON:", err)
			continue
		}

		if _, err := ef.currentFile.Write(append(jsonData, '\n')); err != nil {
			LogMessage(LOG_ERROR, "Failed to write event to file:", err)
		}
	}

	LogMessage(LOG_VERBOSE, fmt.Sprintf("Successfully wrote %d events to %s", len(events), ef.currentFilePath))
}

// checkAndRotateFile checks if file rotation is needed and performs it
func (ef *EventForwarder) checkAndRotateFile() error {
	now := time.Now().UTC()
	rotateNeeded := false

	// Check time-based rotation
	if ef.config.File.RotateMinutes > 0 {
		if ef.lastRotation.IsZero() {
			ef.lastRotation = now
		} else if now.Sub(ef.lastRotation).Minutes() >= float64(ef.config.File.RotateMinutes) {
			rotateNeeded = true
		}
	}

	// Check size-based rotation
	if !rotateNeeded && ef.config.File.MaxFileSize > 0 && ef.currentFile != nil {
		if stat, err := ef.currentFile.Stat(); err == nil {
			fileSizeMB := stat.Size() / (1024 * 1024)
			if fileSizeMB >= int64(ef.config.File.MaxFileSize) {
				rotateNeeded = true
			}
		}
	}

	if rotateNeeded {
		return ef.rotateFile()
	}

	return nil
}

// rotateFile performs the actual file rotation
func (ef *EventForwarder) rotateFile() error {
	// Close current file if open
	if ef.currentFile != nil {
		ef.currentFile.Close()
		ef.currentFile = nil
	}

	// Clean up old files if retention limit is set
	if ef.config.File.RetainFiles > 0 {
		ef.cleanOldFiles()
	}

	// Update rotation time
	ef.lastRotation = time.Now().UTC()

	// Open new file
	return ef.openNewFile()
}

// openNewFile creates a new log file with timestamp naming convention
func (ef *EventForwarder) openNewFile() error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(ef.config.File.DirectoryPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Generate filename with timestamp: YYYYMMDDHHMM_fastfinder_logs.jsonl
	now := time.Now().UTC()
	filename := fmt.Sprintf("%s_fastfinder_logs.jsonl", now.Format("200601021504"))
	ef.currentFilePath = filepath.Join(ef.config.File.DirectoryPath, filename)

	// Open new file
	file, err := os.OpenFile(ef.currentFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", ef.currentFilePath, err)
	}

	ef.currentFile = file
	return nil
}

// cleanOldFiles removes old log files beyond the retention limit
func (ef *EventForwarder) cleanOldFiles() {
	files, err := filepath.Glob(filepath.Join(ef.config.File.DirectoryPath, "*_fastfinder_logs.jsonl"))
	if err != nil {
		return
	}

	// Sort files by name (which includes timestamp)
	sort.Strings(files)

	// Remove oldest files if we exceed retention limit
	if len(files) >= ef.config.File.RetainFiles {
		filesToRemove := len(files) - ef.config.File.RetainFiles + 1
		for i := 0; i < filesToRemove; i++ {
			os.Remove(files[i])
		}
	}
}

// StopEventForwarding stops the event forwarding system
func StopEventForwarding() {
	if eventForwarder != nil {
		close(eventForwarder.stopChannel)
		eventForwarder.wg.Wait()

		// Close current file if open
		if eventForwarder.currentFile != nil {
			eventForwarder.currentFile.Close()
			eventForwarder.currentFile = nil
		}
		eventForwarder = nil
	}
}
