//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed resources/windows_sfx.exe
var sfxBinary []byte
var tempFolder = "%TEMP%"

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

// CheckCurrentUserPermissions retieves the current user permissions and check if the program run with elevated privileges
func CheckCurrentUserPermissions() (admin bool, elevated bool) {
	var err error
	var sid *windows.SID
	err = windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) SID Error: %s", err))
		return false, false
	}
	defer windows.FreeSid(sid)
	token := windows.Token(0)

	admin, err = token.IsMember(sid)
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) Token Membership Error: %s", err))
		return false, false
	}

	return admin, token.IsElevated()
}

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
		return []DriveInfo{}, []string{}
	} else {
		drives = bitsToDrives(uint32(ret))
	}

	for _, drive := range drives {
		var driveInfo DriveInfo
		driveInfo.Name = drive + ":\\"
		drivePtr, err := syscall.UTF16PtrFromString(drive + ":")
		if err != nil {
			return drivesInfo, []string{}
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
