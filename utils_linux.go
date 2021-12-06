//go:build linux

// export CGO_CFLAGS="-I/opt/yara-4.1.3/libyara/include"
// export CGO_LDFLAGS="-L/opt/yara-4.1.3/libyara/.libs -lyara"

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
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

func (c *cmdRunner) Exec(cmd string, args []string) string {
	command := exec.Command(cmd, args...)
	outputBytes, _ := command.CombinedOutput()
	return string(outputBytes[:])
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
		return drivesInfo, excludedPaths
	}

	for _, disk := range disks {
		if disk["mountpoint"] != "" {
			switch disk["type"] {
			case "part":
				if isUSBStorage("/dev/" + disk["name"]) {
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

	return drivesInfo, excludedPaths
}

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

func isUSBStorage(device string) bool {
	deviceVerifier := "ID_USB_DRIVER=usb-storage"
	cmd := "udevadm"
	args := []string{"info", "-q", "property", "-n", device}
	out, err := exec.Command(cmd, args...).Output()

	if err != nil {
		LogMessage(LOG_ERROR, "[ERROR]", "Error checking device %s: %s", device, err)
		return false
	}

	if strings.Contains(string(out), deviceVerifier) {
		return true
	}

	return false
}
