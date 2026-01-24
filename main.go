// #cgo !yara_no_pkg_config,!yara_static  pkg-config: yara
// #cgo !yara_no_pkg_config,yara_static   pkg-config: --static yara
// #cgo yara_no_pkg_config                LDFLAGS:    -lyara
// compile: go build -trimpath -tags yara_static -a -ldflags '-s -w -extldflags "-static"' .
// suggestion: reduce binary size with "upx --best --lzma .\fastfinder.exe"

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/akamensky/argparse"
	"github.com/dlclark/regexp2"
	"github.com/fsnotify/fsnotify"
	"github.com/hillu/go-yara/v4"
)

const FASTFINDER_VERSION = "3.0.0"
const YARA_VERSION = "4.5.5"
const BUILDER_RC4_KEY = ">Õ°ªKb{¡§ÌB$lMÕ±9l.tòÑé¦Ø¿"

func main() {
	// parse configuration file
	parser := argparse.NewParser("fastfinder", "Fastfinder v"+FASTFINDER_VERSION+" (with YARA "+YARA_VERSION+")"+LineBreak+"\t\t\tIncident Response - Fast suspicious file finder")
	pConfigPath := parser.String("c", "configuration", &argparse.Options{Required: false, Default: "", Help: "Fastfind configuration file"})
	pSfxPath := parser.String("b", "build", &argparse.Options{Required: false, Help: "Output a standalone package with configuration and rules in a single binary"})
	pSilentMode := parser.Flag("s", "silent", &argparse.Options{Required: false, Help: "Silent mode - run without any visible window or console"})
	pLogVerbosity := parser.Int("v", "verbosity", &argparse.Options{Required: false, Default: 3, Help: "File log verbosity \n\t\t\t\t | 1: Only alerts\n\t\t\t\t | 2: Alerts and warnings\n\t\t\t\t | 3: Alerts,warnings and errors\n\t\t\t\t | 4: Alerts,warnings,errors and I/O operations\n\t\t\t\t | 5: Full verbosity)\n\t\t\t\t"})
	pTriage := parser.Flag("t", "triage", &argparse.Options{Required: false, Default: false, Help: "Triage mode (infinite run - scan every new file in the input path directories)"})
	pRootPath := parser.String("r", "root", &argparse.Options{Required: false, Default: "", Help: "Scan root path (override drive enumeration to scan specific directory)"})

	// handle argument parsing error
	err := parser.Parse(os.Args)
	if err != nil {
		log.Fatal(parser.Usage(err))
	}

	// Determine if any parameter (other than program name) was provided
	hasParameters := len(os.Args) > 1

	RunProgramWithParameters(*pConfigPath, *pSfxPath, *pSilentMode, *pLogVerbosity, *pTriage, *pRootPath, hasParameters)
}

// RunProgramWithParameters used specified argv and run fastfinder
func RunProgramWithParameters(pConfigPath string, pSfxPath string, pSilentMode bool, pLogVerbosity int, pTriage bool, pRootPath string, hasParameters bool) {
	// Silent mode: no output at all
	if pSilentMode {
		UIactive = false
		loggingVerbosity = 0 // Suppress all logging
	}

	// Determine mode:
	// - No parameters at all: tview UI mode (default)
	// - Has parameters: Console mode (no UI)
	// - Has SFX: Build mode (console, no UI)

	if pSilentMode || len(pSfxPath) > 0 || hasParameters {
		// Silent mode, SFX build mode, or has parameters - no UI
		UIactive = false
	} else {
		// Default: Use tview UI only when no parameters provided
		InitUI()
	}

	// display open file dialog when config file empty and UI is active
	if len(pConfigPath) == 0 && UIactive {
		OpenFileDialog()
		pConfigPath = UIselectedConfigPath
	}

	// configuration parsing
	var config Configuration
	config.getConfiguration(pConfigPath)
	if config.Output.FilesCopyPath != "" {
		config.Output.FilesCopyPath = "./"
	}

	// file logging verbosity
	if pLogVerbosity >= 1 && pLogVerbosity <= 5 {
		loggingVerbosity = pLogVerbosity
	}

	// run app
	if UIactive {
		go MainFastfinderRoutine(config, pConfigPath, false, pSfxPath, pTriage, pLogVerbosity, pRootPath)
		MainWindow()
	} else {
		fmt.Print(LineBreak + "================================================" + LineBreak + RenderFastfinderLogo() + "================================================" + LineBreak)
		MainFastfinderRoutine(config, pConfigPath, false, pSfxPath, pTriage, pLogVerbosity, pRootPath)
	}

}

// MainFastfinderRoutine is used in every scan routine and based on config file directives
func MainFastfinderRoutine(config Configuration, pConfigPath string, pNoAdvUI bool, pSfxPath string, pTriage bool, pLoglevel int, pRootPath string) {
	var rules *yara.Rules

	// Tracking variables for event forwarding
	scanStartTime := time.Now()
	var totalFilesScanned int
	var totalMatchesFound int
	var totalErrorsEncountered int

	// check for input configuration
	if len(config.Input.Path) == 0 && len(config.Input.Content.Grep) == 0 && len(config.Input.Content.Checksum) == 0 && len(config.Input.Content.Yara) == 0 {
		LogMessage(LOG_ERROR, "(ERROR)", "Input parameters empty - cannot find any item")
		ExitProgram(1, !UIactive)
	}

	// sfx building option
	if len(pSfxPath) > 0 {
		if runtime.GOARCH != "amd64" {
			LogMessage(LOG_ERROR, "(ERROR)", "SFX build is only supported on x64 (amd64) architecture")
			ExitProgram(1, !UIactive)
		}
		BuildSFX(pConfigPath, pSfxPath, pLoglevel, pNoAdvUI)
		LogMessage(LOG_INFO, "(INFO)", "Fastfinder package generated successfully at", pSfxPath)
		ExitProgram(0, !UIactive)
	}

	// fastfinder init
	FastFinderInit(config, pConfigPath, pSfxPath)

	// Initialize event forwarding if configured
	if config.EventForwarding.Enabled {
		err := InitializeEventForwarding(&config.EventForwarding)
		if err != nil {
			LogMessage(LOG_ERROR, "Failed to initialize event forwarding:", err)
		} else {
			LogMessage(LOG_INFO, "Event forwarding initialized successfully")
			// Forward scan start event
			ForwardEvent("scan_start", "info", "FastFinder scan started", map[string]string{
				"config_path": pConfigPath,
				"version":     FASTFINDER_VERSION,
			})
		}
	}

	// if yara rules mentionned - compile them
	if len(config.Input.Content.Yara) > 0 {
		rules = CompileYaraRules(config.Input.Content.Yara, config.AdvancedParameters.YaraRC4Key)
	}

	// Memory Scan
	if config.Options.ScanMemory {
		ScanMemory(config, rules)
	}

	// drives enumeration
	var baseDrives []string
	var excludedPaths []string

	if len(pRootPath) > 0 {
		LogMessage(LOG_INFO, "(INIT)", "Using custom scan root:", pRootPath)
		baseDrives = []string{pRootPath}
		excludedPaths = []string{}
	} else if len(config.Input.DirectPaths) > 0 {
		LogMessage(LOG_INFO, "(INIT)", "Using explicit paths from configuration")
		baseDrives = config.Input.DirectPaths
		excludedPaths = []string{}
	} else {
		baseDrives, excludedPaths = DriveEnumeration(config)
	}

	// triage mode start
	if pTriage {
		if len(config.Input.Path) == 0 {
			LogFatal("No initial path specified to look for in triage mode")
		}

		if len(config.Input.Content.Yara) == 0 && len(config.Input.Content.Checksum) == 0 && len(config.Input.Content.Grep) == 0 {
			LogFatal("No criteria to look for in triage mode")
		}

		if config.Options.FindInNetworkDrives || config.Options.FindInCDRomDrives {
			LogMessage(LOG_ERROR, "(WARNING)", "Triage mode cannot retrieve files modification on network and CD-ROM drives")
			time.Sleep(3 * time.Second)
		}

		if !pNoAdvUI {
			UIactive = false
			LogMessage(LOG_INFO, "(INFO)", "Advanced UI disabled for performance enhancements under triage")
		}

		LogMessage(LOG_INFO, "(INFO)", "TRIAGE MODE - Use Ctrl+C to stop fastfinder")
		time.Sleep(3 * time.Second)
		InitTriageScan(config, rules, baseDrives, excludedPaths)
	}

	// start main routine
	for _, basePath := range baseDrives {
		LogMessage(LOG_VERBOSE, "(INFO)", "Enumerating files in", basePath)

		// Calculate excluded paths for this base path
		var currentExcludedPaths []string
		currentExcludedPaths = append(currentExcludedPaths, excludedPaths...)

		if runtime.GOOS != "windows" {
			// Exclude other base drives that are subdirectories of the current base path
			for _, otherPath := range baseDrives {
				if otherPath != basePath && strings.HasPrefix(otherPath, basePath) {
					currentExcludedPaths = append(currentExcludedPaths, otherPath)
				}
			}
		}

		// Prepare path regex patterns
		var pathRegexPatterns []*regexp2.Regexp
		if len(config.Input.Path) > 0 {
			LogMessage(LOG_VERBOSE, "(INFO)", "Checking for paths matchs in", basePath)
			for _, pattern := range config.Input.Path {
				re := regexp2.MustCompile(pattern, regexp2.IgnoreCase)
				pathRegexPatterns = append(pathRegexPatterns, re)
			}
		}

		// Create scanner pipeline with buffer for concurrent operations
		pipeline := NewScannerPipeline(1000)

		// Start enumeration in a separate goroutine
		LogMessage(LOG_VERBOSE, "(INFO)", "Starting file enumeration in", basePath)
		pipeline.StartEnumeration([]string{basePath}, currentExcludedPaths)

		// Start scanning based on configuration
		if len(config.Input.Content.Grep) > 0 || len(config.Input.Content.Checksum) > 0 || len(config.Input.Content.Yara) > 0 {
			LogMessage(LOG_VERBOSE, "(INFO)", "Starting content scanning in", basePath)
			pipeline.StartScanning(
				config.Input.Content.Grep,
				rules,
				config.Input.Content.Checksum,
				config.AdvancedParameters.MaxScanFilesize,
				config.AdvancedParameters.CleanMemoryIfFileGreaterThanSize,
				pathRegexPatterns,
				config.Options.ContentMatchDependsOnPathMatch)
		} else if len(pathRegexPatterns) > 0 {
			// Only path scanning, no content scanning
			LogMessage(LOG_VERBOSE, "(INFO)", "Starting path pattern matching in", basePath)
			pipeline.StartScanningPathOnly(pathRegexPatterns)
		}

		// Collect matches as they are found
		var matchingFiles []string
		matchesDone := make(chan bool, 1)
		go func() {
			for match := range pipeline.GetMatches() {
				if !Contains(matchingFiles, match) {
					matchingFiles = append(matchingFiles, match)
				}
			}
			matchesDone <- true
		}()

		// Wait for enumeration and scanning to complete
		pipeline.WaitEnumeration()
		pipeline.WaitScanning()
		pipeline.WaitAll()

		// Wait for matches collection to complete
		<-matchesDone

		// Update stats
		totalFilesScanned += int(pipeline.GetFilesScanned())
		totalErrorsEncountered += int(pipeline.GetErrorsEncountered())
		totalMatchesFound += len(matchingFiles)

		// listing and copy matching files
		LogMessage(LOG_INFO, "(INFO)", "scan finished in", basePath)
		if len(matchingFiles) > 0 {
			LogMessage(LOG_ALERT, "(INFO)", "Matching files: ")
			for i := 0; i < len(matchingFiles); i++ {
				LogMessage(LOG_ALERT, " |", matchingFiles[i])
			}

			// copy file matchs
			if config.Output.CopyMatchingFiles {
				LogMessage(LOG_INFO, "(INFO)", "Copy all matching files")
				for i := 0; i < len(matchingFiles); i++ {
					FileCopy(matchingFiles[i], config.Output.FilesCopyPath, config.Output.Base64Files)
				}
			}
		} else {
			LogMessage(LOG_INFO, "(INFO)", "No match found")
		}
	}

	// Calculate scan duration and send completion event
	scanDuration := time.Since(scanStartTime)

	// Forward scan completion event if event forwarding is enabled
	if config.EventForwarding.Enabled {
		ForwardScanCompleteEvent(totalFilesScanned, totalMatchesFound, totalErrorsEncountered, scanDuration)

		// Stop event forwarding
		StopEventForwarding()
	}

	LogMessage(LOG_ALERT, "(INFO)", fmt.Sprintf("Scan completed in %v", scanDuration))
	LogMessage(LOG_ALERT, "(INFO)", fmt.Sprintf("Files scanned: %d, Matches found: %d, Errors: %d",
		totalFilesScanned, totalMatchesFound, totalErrorsEncountered))

	ExitProgram(0, !UIactive)
}

// FastFinderInit return basic host informations / check for mutex and return current user permissions
func FastFinderInit(config Configuration, pConfigPath string, pSfxPath string) {
	var err error

	LogMessage(LOG_INFO, "(INIT)", "Fastfinder v"+FASTFINDER_VERSION+" with embedded YARA v"+YARA_VERSION)
	LogMessage(LOG_INFO, "(INIT)", "OS:", runtime.GOOS, "Arch:", runtime.GOARCH)
	LogMessage(LOG_INFO, "(INIT)", "Hostname:", GetHostname())
	LogMessage(LOG_INFO, "(INIT)", "User:", GetUsername())
	LogMessage(LOG_INFO, "(INIT)", "Current directory:", GetCurrentDirectory())
	LogMessage(LOG_INFO, "(INIT)", "Max file size scan:", fmt.Sprintf("%dMB", config.AdvancedParameters.MaxScanFilesize))
	LogMessage(LOG_INFO, "(INIT)", "Config file:", pConfigPath)

	// Resolve executable path (handles cases where binary is in PATH)
	execPath := os.Args[0]
	if !filepath.IsAbs(execPath) {
		if absPath, err := exec.LookPath(execPath); err == nil {
			execPath = absPath
		} else if absPath, err := filepath.Abs(execPath); err == nil {
			execPath = absPath
		}
	}
	LogMessage(LOG_INFO, "(INIT)", "Fastfinder executable SHA256 checksum:", FileSHA256Sum(execPath))
	LogMessage(LOG_INFO, "(INIT)", "Configuration file SHA256 checksum:", FileSHA256Sum(pConfigPath))

	if len(pSfxPath) == 0 {
		disableMutex := os.Getenv("FASTFINDER_DISABLE_MUTEX") == "1"
		if !disableMutex {
			// create mutex
			if _, err = CreateMutex("fastfinder"); err != nil {
				LogMessage(LOG_ERROR, "(ERROR)", "Only one instance or fastfinder can be launched:", err.Error())
				ExitProgram(1, !UIactive)
			}
		} else {
			LogMessage(LOG_INFO, "(INIT)", "Mutex disabled via FASTFINDER_DISABLE_MUTEX=1 (container mode)")
		}

		// Retrieve current user permissions
		admin, elevated := CheckCurrentUserPermissions()
		if !admin && !elevated {
			LogMessage(LOG_ERROR, "(WARNING) fastfinder is not running with fully elevated righs. Notice that the analysis will be partial and limited to the current user scope")
		}
	}
}

// DriveEnumeration enumerate drives based on configuration parameters
func DriveEnumeration(config Configuration) ([]string, []string) {
	LogMessage(LOG_VERBOSE, "(INIT)", "Enumerating drives")
	var basePaths []string
	drives, excludedPaths := EnumLogicalDrives()

	if len(drives) == 0 {
		LogMessage(LOG_ERROR, "(ERROR)", "Unable to find drives")
		ExitProgram(1, !UIactive)
	}

	for _, drive := range drives {
		if (drive.Type == DRIVE_REMOVABLE && config.Options.FindInRemovableDrives) ||
			(drive.Type == DRIVE_FIXED && config.Options.FindInHardDrives) ||
			(drive.Type == DRIVE_REMOTE && config.Options.FindInNetworkDrives) ||
			(drive.Type == DRIVE_CDROM && config.Options.FindInCDRomDrives) {
			if runtime.GOOS == "windows" || len(basePaths) == 0 {
				basePaths = append(basePaths, drive.Name)
			} else {
				alreadyParsed := false
				for _, p := range basePaths {
					if len(drive.Name) > len(p) && !strings.HasPrefix(drive.Name, p) {
						alreadyParsed = true
					}
				}
				if !alreadyParsed {
					basePaths = append(basePaths, drive.Name)
				}
			}
		} else {
			if runtime.GOOS != "windows" {
				excludedPaths = append(excludedPaths, drive.Name)
			}
		}
	}

	if len(basePaths) == 0 {
		LogMessage(LOG_ERROR, "(ERROR)", "No drive corresponding to your configuration drive type")
		ExitProgram(1, !UIactive)
	} else {
		LogMessage(LOG_VERBOSE, "(INIT)", "Looking for the following drives:")
		for _, p := range basePaths {
			LogMessage(LOG_INFO, " |", p)
		}
	}

	if len(excludedPaths) > 0 {
		LogMessage(LOG_VERBOSE, "(INFO)", "Excluding the following paths:")
		for _, p := range excludedPaths {
			LogMessage(LOG_INFO, " |", p)
		}
	}

	if len(config.Input.Path) > 0 {
		LogMessage(LOG_VERBOSE, "(INIT)", "Searching for the following paths patterns in your drives:")
		for _, p := range config.Input.Path {
			LogMessage(LOG_INFO, " |", p)
		}
	}

	if runtime.GOOS != "windows" {
		sort.Slice(basePaths, func(i, j int) bool {
			return len(basePaths[i]) > len(basePaths[j])
		})
	}

	return basePaths, excludedPaths
}

// InitTriageScan convert fastfinder scan routine to triage infinite scan
func InitTriageScan(config Configuration, rules *yara.Rules, baseDrives []string, excludedPaths []string) {
	// init filesystem watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// enumerate drive paths and add paths to watch
	var pathsEnumeration []string
	for _, drive := range baseDrives {
		pathsEnumeration = append(pathsEnumeration, *ListDirectoryRecursively(drive, excludedPaths)...)
	}

	var pathRegexPatterns []*regexp2.Regexp
	for _, pattern := range config.Input.Path {
		re := regexp2.MustCompile(pattern, regexp2.IgnoreCase)
		pathRegexPatterns = append(pathRegexPatterns, re)
	}

	for _, p := range *PathsFinder(&pathsEnumeration, pathRegexPatterns) {
		LogMessage(LOG_INFO, "(INFO)", "Add to watchlist:", p)
		err = watcher.Add(p)
		if err != nil {
			LogFatal(fmt.Sprintf("watcher error %v", err))
		}
	}

	LogMessage(LOG_INFO, "(INFO)", "==== TRIAGE SCAN INITIALIZATION FINISHED - READY TO SCAN ===")
	time.Sleep(3 * time.Second)

	// scan routine
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				LogMessage(LOG_VERBOSE, "(INFO)", "Scanning file:", event.Name)
				time.Sleep(500 * time.Millisecond)
				m := FindInFilesContent(&[]string{event.Name}, config.Input.Content.Grep, rules, config.Input.Content.Checksum, true, config.AdvancedParameters.MaxScanFilesize, config.AdvancedParameters.CleanMemoryIfFileGreaterThanSize)
				if len(*m) > 0 && config.Output.CopyMatchingFiles {
					if config.Output.CopyMatchingFiles {
						LogMessage(LOG_VERBOSE, "(INFO)", "Copying file:", event.Name)
						FileCopy(event.Name, config.Output.FilesCopyPath, config.Output.Base64Files)
					}
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			LogMessage(LOG_ERROR, "Watcher error:", err)
		}
	}
}
