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

type Env struct {
	Name  string
	Value string
}

type DriveInfo struct {
	Name string
	Type uint32
}

const (
	DRIVE_UNKNOWN     = 0
	DRIVE_NO_ROOT_DIR = 1
	DRIVE_REMOVABLE   = 2
	DRIVE_FIXED       = 3
	DRIVE_REMOTE      = 4
	DRIVE_CDROM       = 5
	DRIVE_RAMDISK     = 6
)

var (
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procCreateMutex      = modKernel32.NewProc("CreateMutexW")
	procGetLogicalDrives = modKernel32.NewProc("GetLogicalDrives")
	procGetDriveTypeW    = modKernel32.NewProc("GetDriveTypeW")
)

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

func getEnvironmentVariables() (environmentVariables []Env) {
	for _, item := range os.Environ() {
		envPair := strings.SplitN(item, "=", 2)
		env := Env{
			Name:  envPair[0],
			Value: envPair[1],
		}
		environmentVariables = append(environmentVariables, env)
	}

	return environmentVariables
}

func listFilesRecursively(path string) (files []string) {
	err := filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			log.Println(err)
			return filepath.SkipDir
		}

		if !f.IsDir() {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		log.Println(err)
	}

	return files
}

func enumLogicalDrives() (drivesInfo []DriveInfo) {
	var drives []string
	if ret, _, callErr := procGetLogicalDrives.Call(); callErr != windows.ERROR_SUCCESS {
		return []DriveInfo{}
	} else {
		drives = bitsToDrives(uint32(ret))
	}

	for _, drive := range drives {
		var driveInfo DriveInfo
		driveInfo.Name = drive
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

	return drivesInfo
}

func bitsToDrives(bits uint32) (drives []string) {
	for i := 0; i < 26; i++ {
		if bits&(1<<uint(i)) != 0 {
			drives = append(drives, string('A'+i))
		}
	}
	return drives
}

func FileCopy(src, dst string, base64Encode bool) {
	dst += filepath.Base(src) + ".fastfinder"
	srcFile, err := os.Open(src)
	if err != nil {
		log.Fatal(err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		log.Fatal(err)
	}
	defer dstFile.Close()

	if base64Encode {
		encoder := base64.NewEncoder(base64.StdEncoding, dstFile)
		defer encoder.Close()

		_, err = io.Copy(encoder, srcFile)
	} else {
		_, err = io.Copy(dstFile, srcFile)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
