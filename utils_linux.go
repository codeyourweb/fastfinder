//go:build linux

package main

import (
	"encoding/base64"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

type Env struct {
	Name  string
	Value string
}

// HideConsoleWindow hide the process console window
func HideConsoleWindow() {
	LogMessage(LOG_INFO, "[COMPAT]", "Hide console not implented on linux. You should consider run this program as a task")
}

// CreateMutex creates a named mutex to avoid multiple instance run
func CreateMutex(name string) (uintptr, error) {
	return 0, nil
}

// EnumLogicalDrives returns a list of all logical drives letters on the system.
func EnumLogicalDrives() (drivesInfo []DriveInfo) {
	return drivesInfo
}
