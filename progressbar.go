package main

import "github.com/schollz/progressbar/v3"

var progressbarEnabled bool
var bar *progressbar.ProgressBar

func EnableProgressbar(enable bool) {
	progressbarEnabled = enable
}

func InitProgressbar(value int64) {
	if progressbarEnabled {
		bar = progressbar.Default(value)
	}
}

func ProgressBarStep() {
	if progressbarEnabled {
		bar.Add(1)
	}
}
