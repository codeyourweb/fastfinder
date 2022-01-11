//go:build linux

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const LineBreak = "\n"

type disks map[string]map[string]string
type cmdRunner struct{}

func New() *cmdRunner {
	return &cmdRunner{}
}

func (c *cmdRunner) Run(cmd string, args []string) (io.Reader, error) {
	command := exec.Command(cmd, args...)
	resCh := make(chan []byte)
	errCh := make(chan error)
	go func() {
		out, err := command.CombinedOutput()
		if err != nil {
			errCh <- err
		}
		resCh <- out
	}()
	timer := time.After(2 * time.Second)
	select {
	case err := <-errCh:
		return nil, err
	case res := <-resCh:
		return bytes.NewReader(res), nil
	case <-timer:
		return nil, fmt.Errorf("time out (cmd:%v args:%v)", cmd, args)
	}
}

// CheckCurrentUserPermissions retieves the current user permissions and check if the program run with elevated privileges
func CheckCurrentUserPermissions() (admin bool, elevated bool) {
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()

	if err != nil {
		log.Fatalf("{ERROR} Error finding current user privileges: %s", err)
	}

	i, err := strconv.Atoi(string(output[:len(output)-1]))
	if err != nil {
		log.Fatalf("{ERROR} Error finding current user privileges: %s", err)
	}

	return i == 0, i == 0
}

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
func EnumLogicalDrives() (drivesInfo []DriveInfo, excludedPaths []string) {
	excludedPaths = []string{"/dev", "/lost+found", "/proc", "/media/floppy"}
	disks, err := Lsblk()
	if err != nil {
		LogMessage(LOG_ERROR, "[COMPAT]", "Error getting disks info: %v - try to parse from /", err)
	} else {
		// Get fixed / removable / cdrom drives
		for _, disk := range disks {
			if disk["mountpoint"] != "" {
				switch disk["type"] {
				case "part":
					if IsUSBStorage("/dev/" + disk["name"]) {
						drivesInfo = append(drivesInfo, DriveInfo{Name: disk["mountpoint"], Type: DRIVE_REMOVABLE})
					} else {
						drivesInfo = append(drivesInfo, DriveInfo{Name: disk["mountpoint"], Type: DRIVE_FIXED})
					}
				case "rom":
					drivesInfo = append(drivesInfo, DriveInfo{Name: disk["mountpoint"], Type: DRIVE_CDROM})
				default:
					excludedPaths = append(excludedPaths, disk["mountpoint"])

				}
			}
		}
	}

	// Get network drives
	nDrives, err := FindInNetworkDrives()
	if err != nil {
		LogMessage(LOG_ERROR, "[COMPAT]", "Error getting network drives: %v", err)
	}

	for _, driveName := range nDrives {
		drivesInfo = append(drivesInfo, DriveInfo{Name: driveName, Type: DRIVE_REMOTE})
	}

	return drivesInfo, excludedPaths
}

// FindInNetworkDrives uses  df -aT and returns a list of all valid fuse mount
func FindInNetworkDrives() (mounts []string, err error) {
	out, err := exec.Command("df", "-aT").Output()
	if err != nil {
		return mounts, err
	}

	outlines := strings.Split(string(out), "\n")

	for _, line := range outlines {
		parsedLine := strings.Fields(line)
		if len(line) > 5 &&
			strings.HasPrefix(parsedLine[len(parsedLine)-1], "/") &&
			(strings.Contains(parsedLine[0], "fuse") || strings.Contains(parsedLine[1], "fuse")) {
			a, _ := strconv.ParseInt(parsedLine[3], 10, 64)
			b, _ := strconv.ParseInt(parsedLine[4], 10, 64)
			if a > 0 && b > 0 {
				mounts = append(mounts, parsedLine[len(parsedLine)-1])
			}
		}
	}

	return mounts, nil
}

// Lsblk returns a map of all disks and their properties
func Lsblk() (disks, error) {
	var cmdrun = cmdRunner{}
	rr, err := cmdrun.Run("lsblk", []string{"-P", "-b", "-o", "NAME,TYPE,MOUNTPOINT"})
	if err != nil {
		return nil, err
	}
	disks := parser_lsblk(rr)
	return disks, nil
}

func parser_lsblk(r io.Reader) map[string]map[string]string {
	var lsblk = make(disks)
	re := regexp.MustCompile("([A-Z]+)=(?:\"(.*?)\")")
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		var disk_name = ""
		disk := make(map[string]string)
		raw := scan.Text()
		sr := re.FindAllStringSubmatch(raw, -1)
		for i, k := range sr {
			k[1] = strings.ToLower(k[1])
			if i == 0 {
				disk_name = k[2]
			}

			if Contains([]string{"name", "type", "mountpoint"}, k[1]) {
				disk[k[1]] = k[2]
			}
		}
		lsblk[disk_name] = disk
	}
	return lsblk
}

// IsUSBStorage returns true if the given device is a USB storage based on udevadm linux command return
func IsUSBStorage(device string) bool {
	deviceVerifier := "ID_USB_DRIVER=usb-storage"
	cmd := "udevadm"
	args := []string{"info", "-q", "property", "-n", device}
	out, err := exec.Command(cmd, args...).Output()

	if err != nil {
		LogMessage(LOG_ERROR, "{ERROR}", "Error checking device %s: %s", device, err)
		return false
	}

	if strings.Contains(string(out), deviceVerifier) {
		return true
	}

	return false
}
