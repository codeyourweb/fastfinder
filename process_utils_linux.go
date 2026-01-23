//go:build linux

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ListProcesses implementation for Linux via /proc filesystem
func ListProcesses() []ProcessInformation {
	var procs []ProcessInformation

	// /proc should exist
	d, err := os.Open("/proc")
	if err != nil {
		LogMessage(LOG_ERROR, "Cannot open /proc:", err)
		return procs
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		LogMessage(LOG_ERROR, "Cannot read /proc:", err)
		return procs
	}

	for _, file := range files {
		if !file.IsDir() {
			continue
		}

		// Check if filename is numeric (PID)
		pid, err := strconv.ParseUint(file.Name(), 10, 32)
		if err != nil {
			continue
		}

		// Get Process Info
		name, path, mem, err := GetProcessDataLinux(uint32(pid))
		if err == nil && len(mem) > 0 {
			if len(name) == 0 {
				name = fmt.Sprintf("Unknown_%d", pid)
			}

			procs = append(procs, ProcessInformation{
				PID:         uint32(pid),
				ProcessName: name,
				ProcessPath: path,
				MemoryDump:  mem,
			})
		}
	}

	return procs
}

func GetProcessDataLinux(pid uint32) (name string, path string, memory []byte, err error) {
	procDir := fmt.Sprintf("/proc/%d", pid)

	// Get Path from /proc/[pid]/exe
	exeLinks, err := os.Readlink(filepath.Join(procDir, "exe"))
	if err == nil {
		path = exeLinks
		name = filepath.Base(path)
	} else {
		// Fallback to cmdline
		cmdline, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
		if err == nil {
			// cmdline arguments are null separated
			parts := bytes.SplitN(cmdline, []byte{0}, 2)
			if len(parts) > 0 && len(parts[0]) > 0 {
				path = string(parts[0])
				name = filepath.Base(path)
			}
		}
	}

	if len(name) == 0 {
		return "", "", nil, fmt.Errorf("could not determine process name")
	}

	// Dump memory from mapped files (modules/libs/binary)
	memory, err = dumpMappedMemory(pid)

	return name, path, memory, err
}

func dumpMappedMemory(pid uint32) ([]byte, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	memPath := fmt.Sprintf("/proc/%d/mem", pid)

	// Open maps file
	mapsFile, err := os.Open(mapsPath)
	if err != nil {
		return nil, err
	}
	defer mapsFile.Close()

	// Open mem file
	memFile, err := os.Open(memPath)
	if err != nil {
		return nil, err
	}
	defer memFile.Close()

	var fullMemory []byte
	scanner := bufio.NewScanner(mapsFile)

	// Parse maps
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// Format: 00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/dbus-daemon
		if len(fields) < 6 {
			continue
		}

		perms := fields[1]
		path := fields[5]

		// Filter: Must be readable "r" and must be associated with a file (not [heap], [stack], or check if path is a file path)
		// To match Windows behavior "EnumProcessModules", we prioritize mapped files.
		// Note: we can interpret special paths like [heap] if we want dynamic memory too, but "Modules" usually implies libs.
		if !strings.Contains(perms, "r") || strings.HasPrefix(path, "[") {
			continue
		}

		// Parse range
		rangeParts := strings.Split(fields[0], "-")
		if len(rangeParts) != 2 {
			continue
		}

		start, err1 := strconv.ParseInt(rangeParts[0], 16, 64)
		end, err2 := strconv.ParseInt(rangeParts[1], 16, 64)

		if err1 != nil || err2 != nil {
			continue
		}

		size := end - start
		if size <= 0 {
			continue
		}

		// Read memory
		buffer := make([]byte, size)
		_, err = memFile.Seek(start, 0) // 0 = io.SeekStart
		if err != nil {
			continue
		}

		_, err = io.ReadFull(memFile, buffer)
		if err == nil {
			fullMemory = append(fullMemory, buffer...)
		}
	}

	return fullMemory, nil
}
