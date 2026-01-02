package main

import (
	"sync"
	"testing"
	"time"
)

// TestScannerPipelineCreation tests pipeline initialization
func TestScannerPipelineCreation(t *testing.T) {
	// Create a new pipeline
	pipeline := NewScannerPipeline(256)

	if pipeline == nil {
		t.Fatal("NewScannerPipeline returned nil")
	}

	// Verify channels are created
	if pipeline.fileChan == nil {
		t.Fatal("fileChan is nil")
	}

	if pipeline.matchesChan == nil {
		t.Fatal("matchesChan is nil")
	}

	if pipeline.errChan == nil {
		t.Fatal("errChan is nil")
	}
}

// TestScannerPipelineChannelSize tests correct channel buffer size
func TestScannerPipelineChannelSize(t *testing.T) {
	bufferSize := 512
	pipeline := NewScannerPipeline(bufferSize)

	if pipeline == nil {
		t.Fatal("Failed to create pipeline")
	}

	// Send data without blocking to verify buffer size
	for i := 0; i < bufferSize; i++ {
		select {
		case pipeline.fileChan <- "test.txt":
			// Successfully sent
		default:
			t.Fatalf("Channel capacity exhausted at %d items (expected %d)", i, bufferSize)
		}
	}
}

// TestScannerPipelineFileChannelWrite tests writing to file channel
func TestScannerPipelineFileChannelWrite(t *testing.T) {
	pipeline := NewScannerPipeline(256)

	if pipeline == nil {
		t.Fatal("Failed to create pipeline")
	}

	// Write to channel
	testFile := "test.txt"
	pipeline.fileChan <- testFile

	// Read it back
	received := <-pipeline.fileChan

	if received != testFile {
		t.Fatalf("Expected %s, got %s", testFile, received)
	}
}

// TestScannerPipelineMatchChannelWrite tests writing to matches channel
func TestScannerPipelineMatchChannelWrite(t *testing.T) {
	pipeline := NewScannerPipeline(256)

	if pipeline == nil {
		t.Fatal("Failed to create pipeline")
	}

	// Write to matches channel
	testMatch := "result.txt: pattern matched"
	pipeline.matchesChan <- testMatch

	// Read it back
	received := <-pipeline.matchesChan

	if received != testMatch {
		t.Fatalf("Expected %s, got %s", testMatch, received)
	}
}

// TestScannerPipelineErrorChannelWrite tests writing to error channel
func TestScannerPipelineErrorChannelWrite(t *testing.T) {
	pipeline := NewScannerPipeline(256)

	if pipeline == nil {
		t.Fatal("Failed to create pipeline")
	}

	// Create a test error
	testErr := error(nil)

	// Write to error channel with a simple error
	pipeline.errChan <- testErr

	// Read it back
	received := <-pipeline.errChan

	if received != testErr {
		t.Fatal("Error channel write/read failed")
	}
}

// TestScannerPipelineConcurrentAccess tests concurrent channel operations
func TestScannerPipelineConcurrentAccess(t *testing.T) {
	pipeline := NewScannerPipeline(256)

	if pipeline == nil {
		t.Fatal("Failed to create pipeline")
	}

	var wg sync.WaitGroup
	numGoroutines := 10
	numItems := 50

	// Writers
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < numItems; j++ {
				pipeline.fileChan <- "test.txt"
			}
		}(i)
	}

	// Close channel after writers done
	go func() {
		wg.Wait()
		close(pipeline.fileChan)
	}()

	// Read all items
	count := 0
	for range pipeline.fileChan {
		count++
	}

	expected := numGoroutines * numItems
	if count != expected {
		t.Fatalf("Expected %d items, got %d", expected, count)
	}
}

// TestScannerPipelineWaitGroup tests WaitGroup functionality
func TestScannerPipelineWaitGroup(t *testing.T) {
	pipeline := NewScannerPipeline(256)

	if pipeline == nil {
		t.Fatal("Failed to create pipeline")
	}

	// Add to wait group
	pipeline.wg.Add(1)

	// Done should decrement
	pipeline.wg.Done()

	// WaitGroup should complete without blocking
	done := make(chan bool)
	go func() {
		pipeline.wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("WaitGroup.Wait() timed out")
	}
}

// TestScannerPipelineEnumerationSignal tests enumeration done signal
func TestScannerPipelineEnumerationSignal(t *testing.T) {
	pipeline := NewScannerPipeline(256)

	if pipeline == nil {
		t.Fatal("Failed to create pipeline")
	}

	// Send enumeration done signal
	go func() {
		pipeline.enumerationDone <- true
	}()

	// Receive signal without blocking
	select {
	case <-pipeline.enumerationDone:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Enumeration signal timed out")
	}
}

// TestScannerPipelineScanningSignal tests scanning done signal
func TestScannerPipelineScanningSignal(t *testing.T) {
	pipeline := NewScannerPipeline(256)

	if pipeline == nil {
		t.Fatal("Failed to create pipeline")
	}

	// Send scanning done signal
	go func() {
		pipeline.scanningDone <- true
	}()

	// Receive signal without blocking
	select {
	case <-pipeline.scanningDone:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Scanning signal timed out")
	}
}

// TestScannerPipelineMultipleBufferSizes tests different buffer sizes
func TestScannerPipelineMultipleBufferSizes(t *testing.T) {
	sizes := []int{1, 10, 100, 1000}

	for _, size := range sizes {
		pipeline := NewScannerPipeline(size)

		if pipeline == nil {
			t.Fatalf("Failed to create pipeline with buffer size %d", size)
		}

		// Send one item
		pipeline.fileChan <- "test.txt"
		received := <-pipeline.fileChan

		if received != "test.txt" {
			t.Fatalf("Buffer size %d: failed to read item", size)
		}
	}
}

// TestScannerPipelineZeroBufferSize tests unbuffered channels
func TestScannerPipelineZeroBufferSize(t *testing.T) {
	pipeline := NewScannerPipeline(0)

	if pipeline == nil {
		t.Fatal("Failed to create pipeline with zero buffer size")
	}

	// Test that synchronous communication works
	go func() {
		pipeline.fileChan <- "test.txt"
	}()

	select {
	case received := <-pipeline.fileChan:
		if received != "test.txt" {
			t.Fatal("Zero buffer size: received wrong value")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Zero buffer size: communication timed out")
	}
}
