//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modpsapi                 = windows.NewLazySystemDLL("psapi.dll")
	procEnumProcesses        = modpsapi.NewProc("EnumProcesses")
	procEnumProcessModules   = modpsapi.NewProc("EnumProcessModules")
	procGetModuleBaseName    = modpsapi.NewProc("GetModuleBaseNameW")
	procGetModuleFileNameEx  = modpsapi.NewProc("GetModuleFileNameExW")
	procGetModuleInformation = modpsapi.NewProc("GetModuleInformation")
)

type MODULEINFO struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

func GetProcessesList() ([]uint32, uint32, error) {
	var pids [4096]uint32
	var bytesReturned uint32
	ret, _, err := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&pids)),
		uintptr(unsafe.Sizeof(pids)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ret == 0 {
		return nil, 0, err
	}

	n := bytesReturned / 4
	return pids[:n], bytesReturned, nil
}

func GetProcessData(pid uint32, hProc windows.Handle) (name string, path string, memory []byte, err error) {
	var modules [1024]syscall.Handle
	var cbNeeded uint32

	// EnumProcessModules to get ALL loaded modules
	ret, _, _ := procEnumProcessModules.Call(
		uintptr(hProc),
		uintptr(unsafe.Pointer(&modules)),
		uintptr(unsafe.Sizeof(modules)),
		uintptr(unsafe.Pointer(&cbNeeded)),
	)
	if ret == 0 {
		return "", "", nil, fmt.Errorf("EnumProcessModules failed")
	}

	count := int(cbNeeded) / int(unsafe.Sizeof(modules[0]))
	if count > 1024 {
		count = 1024
	}

	if count == 0 {
		return "", "", nil, fmt.Errorf("no modules found")
	}

	// 1. Get process name and path from the first module (main executable)
	hModMain := modules[0]

	// Name
	var nameBuf [256]uint16
	ret, _, _ = procGetModuleBaseName.Call(
		uintptr(hProc),
		uintptr(hModMain),
		uintptr(unsafe.Pointer(&nameBuf)),
		uintptr(unsafe.Sizeof(nameBuf)/2),
	)
	if ret != 0 {
		name = syscall.UTF16ToString(nameBuf[:])
	}

	// Path
	var pathBuf [1024]uint16
	ret, _, _ = procGetModuleFileNameEx.Call(
		uintptr(hProc),
		uintptr(hModMain),
		uintptr(unsafe.Pointer(&pathBuf)),
		uintptr(unsafe.Sizeof(pathBuf)/2),
	)
	if ret != 0 {
		path = syscall.UTF16ToString(pathBuf[:])
	}

	// 2. Scan ALL modules
	var fullMemory []byte

	for i := 0; i < count; i++ {
		hMod := modules[i]
		if hMod == 0 {
			continue
		}

		var modInfo MODULEINFO
		ret, _, _ = procGetModuleInformation.Call(
			uintptr(hProc),
			uintptr(hMod),
			uintptr(unsafe.Pointer(&modInfo)),
			uintptr(unsafe.Sizeof(modInfo)),
		)
		if ret == 0 {
			continue
		}

		// Read memory for this module
		buffer := make([]byte, modInfo.SizeOfImage)
		var bytesRead uintptr
		err = windows.ReadProcessMemory(hProc, modInfo.BaseOfDll, &buffer[0], uintptr(modInfo.SizeOfImage), &bytesRead)
		if err == nil && bytesRead > 0 {
			fullMemory = append(fullMemory, buffer...)
		}
	}

	return name, path, fullMemory, nil
}

func ListProcesses() []ProcessInformation {
	var procs []ProcessInformation
	pids, _, err := GetProcessesList()
	if err != nil {
		LogMessage(LOG_ERROR, "Failed to enumerate processes:", err)
		return procs
	}

	for _, pid := range pids {
		if pid == 0 {
			continue
		}

		hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
		if err != nil {
			continue
		}

		name, path, mem, err := GetProcessData(pid, hProc)
		windows.CloseHandle(hProc)

		if err == nil && len(mem) > 0 {
			// Clean memory from null bytes at the end if necessary, or keep as is
			// memory = bytes.Trim(memory, "\x00") // Optional
			if len(name) == 0 {
				name = fmt.Sprintf("Unknown_%d", pid)
			}

			procs = append(procs, ProcessInformation{
				PID:         pid,
				ProcessName: name,
				ProcessPath: path,
				MemoryDump:  mem,
			})
		}
	}
	return procs
}
