package main

import (
	"testing"
)

func TestProgressbar(t *testing.T) {
	if progressbarEnabled {
		t.Fatal("Progressbar global boolean has to be set to false on app start")
	}
	EnableProgressbar(true)
	InitProgressbar(100)

	if !progressbarEnabled {
		t.Fatal("InitProgressbar fails set progressbarEnabled to true")
	}

	if bar.GetMax() != 100 {
		t.Fatal("InitProgressbar fails set bar max value")
	}

	for i := 0; i <= 100; i++ {
		ProgressBarStep()
	}

	if !bar.IsFinished() {
		t.Fatal("ProgressBarStep fails setting progressbar")
	}

	EnableProgressbar(false)
}
