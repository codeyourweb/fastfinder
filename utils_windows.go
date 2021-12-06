//go:build windows

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

	"golang.org/x/sys/windows"
)

const LineBreak = "\r\n"

var (
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	modUser32            = windows.NewLazySystemDLL("user32.dll")
	procCreateMutex      = modKernel32.NewProc("CreateMutexW")
	procGetLogicalDrives = modKernel32.NewProc("GetLogicalDrives")
	procGetDriveTypeW    = modKernel32.NewProc("GetDriveTypeW")
	procGetConsoleWindow = modKernel32.NewProc("GetConsoleWindow")
	procShowWindow       = modUser32.NewProc("ShowWindow")
)

// HideConsoleWindow hide the process console window
func HideConsoleWindow() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}

	procShowWindow.Call(hwnd, 0)
}

// CreateMutex creates a named mutex to avoid multiple instance run
func CreateMutex(name string) (uintptr, error) {
	mutexNamePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}

	ret, _, err := procCreateMutex.Call(0, 0, uintptr(unsafe.Pointer(mutexNamePtr)))
	switch int(err.(syscall.Errno)) {
	case 0:
		return ret, nil
	default:
		return ret, err
	}
}

// EnumLogicalDrives returns a list of all logical drives letters on the system.
func EnumLogicalDrives() (drivesInfo []DriveInfo, excludedPaths []string) {
	var drives []string
	if ret, _, callErr := procGetLogicalDrives.Call(); callErr != windows.ERROR_SUCCESS {
		return []DriveInfo{}
	} else {
		drives = bitsToDrives(uint32(ret))
	}

	for _, drive := range drives {
		var driveInfo DriveInfo
		driveInfo.Name = drive + ":\\"
		drivePtr, err := syscall.UTF16PtrFromString(drive + ":")
		if err != nil {
			return drivesInfo
		}

		if ret, _, callErr := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(drivePtr))); callErr != windows.ERROR_SUCCESS {
			driveInfo.Type = DRIVE_UNKNOWN
		} else {
			driveInfo.Type = uint32(ret)
		}

		drivesInfo = append(drivesInfo, driveInfo)
	}

	return drivesInfo, []string{}
}

// map drive DWORD returned by EnumLogicalDrives to drive letters
func bitsToDrives(bits uint32) (drives []string) {
	for i := 0; i < 26; i++ {
		if bits&(1<<uint(i)) != 0 {
			drives = append(drives, string('A'+i))
		}
	}
	return drives
}
