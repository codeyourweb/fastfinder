//go:build linux

// export CGO_CFLAGS="-I/opt/yara-4.1.3/libyara/include"
// export CGO_LDFLAGS="-L/opt/yara-4.1.3/libyara/.libs -lyara"

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"syscall"
)

const LineBreak = "\n"

// HideConsoleWindow hide the process console window
func HideConsoleWindow() {
	LogMessage(LOG_INFO, "[COMPAT]", "Hide console option not implented on linux. You should consider run this program as a task")
}

// CreateMutex creates a named mutex to avoid multiple instance run
func CreateMutex(name string) (uintptr, error) {
	lockFile := "fastfinder.lock"
	currentPid := os.Getpid()

	lockContent, err := ioutil.ReadFile(lockFile)
	if err == nil {
		if len(lockContent) > 0 && string(lockContent) != fmt.Sprintf("%d", currentPid) {
			lockProcessId, _ := strconv.Atoi(string(lockContent))
			process, err := os.FindProcess(lockProcessId)
			if err == nil {
				pSignal := process.Signal(syscall.Signal(0))
				if pSignal == nil {
					return uintptr(currentPid), fmt.Errorf("another instance of fastfinder is running")
				}
			}
		}
	}

	f, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0664)
	if err != nil {
		return 0, fmt.Errorf("cannot instanciate mutex")
	}
	defer f.Close()
	f.Write([]byte(fmt.Sprintf("%d", currentPid)))

	return uintptr(currentPid), nil
}

// EnumLogicalDrives returns a list of all logical drives letters on the system.
func EnumLogicalDrives() (drivesInfo []DriveInfo) {
	drivesInfo = append(drivesInfo, DriveInfo{Name: "/", Type: DRIVE_FIXED})
	return drivesInfo
}
