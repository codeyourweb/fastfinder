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
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/akamensky/argparse"
	"github.com/dlclark/regexp2"
	"github.com/hillu/go-yara/v4"
)

const FASTFINDER_VERSION = "2.0.0b"
const YARA_VERSION = "4.1.3"
const BUILDER_RC4_KEY = ">Õ°ªKb{¡§ÌB$lMÕ±9l.tòÑé¦Ø¿"

func main() {
	var compiler *yara.Compiler
	var rules *yara.Rules
	var err error

	PrintFastfinderLogo()

	// parse configuration file
	parser := argparse.NewParser("fastfinder", "Incident Response - Fast suspicious file finder")
	pConfigPath := parser.String("c", "configuration", &argparse.Options{Required: false, Default: "configuration.yaml", Help: "Fastfind configuration file"})
	pSfxPath := parser.String("b", "build", &argparse.Options{Required: false, Help: "Output a standalone package with configuration and rules in a single binary"})
	pOutLogPath := parser.String("o", "output", &argparse.Options{Required: false, Help: "Save fastfinder logs in the specified file"})
	pHideWindow := parser.Flag("n", "nowindow", &argparse.Options{Required: false, Help: "Hide fastfinder window"})
	pShowProgress := parser.Flag("p", "showprogress", &argparse.Options{Required: false, Help: "Display I/O analysis progress"})
	pFinderVersion := parser.Flag("v", "version", &argparse.Options{Required: false, Help: "Display fastfinder version"})

	err = parser.Parse(os.Args)
	if err != nil {
		log.Fatal(parser.Usage(err))
	}

	// version
	if *pFinderVersion {
		fmt.Println("fastfinder v" + FASTFINDER_VERSION + " with embedded YARA v" + YARA_VERSION)
		if !Contains(os.Args, "-c") && !Contains(os.Args, "--configuration") {
			os.Exit(0)
		}
	}

	// progressbar
	EnableProgressbar(*pShowProgress)

	// configuration parsing
	var config Configuration
	config.getConfiguration(*pConfigPath)
	if config.Output.FilesCopyPath != "" {
		config.Output.FilesCopyPath = "./"
	}

	// window hidden
	if *pHideWindow && len(*pSfxPath) == 0 {
		HideConsoleWindow()
	}

	// init file logging
	if len(*pOutLogPath) > 0 && len(*pSfxPath) == 0 {
		StdoutToLogFile(*pOutLogPath)
		StderrToLogFile(*pOutLogPath)
	}

	// check for input configuration
	if len(config.Input.Path) == 0 && len(config.Input.Content.Grep) == 0 && len(config.Input.Content.Yara) == 0 {
		LogMessage(LOG_ERROR, "[ERROR]", "Input parameters empty - cannot find any item")
		os.Exit(1)
	}

	// sfx building option
	if len(*pSfxPath) > 0 {
		if runtime.GOOS != "windows" {
			LogMessage(LOG_ERROR, "[ERROR]", "Standalone package can be built only on Windows")
			os.Exit(1)
		}
		BuildSFX(config, *pSfxPath, *pOutLogPath, *pHideWindow)
		LogMessage(LOG_INFO, "[INFO]", "Fastfinder package generated successfully at", *pSfxPath)
		os.Exit(0)
	}

	// fastfinder init
	LogMessage(LOG_INFO, "[INIT]", "Fastfinder v"+FASTFINDER_VERSION+" with embedded YARA v"+YARA_VERSION)
	LogMessage(LOG_INFO, "[INIT]", "OS:", runtime.GOOS, "Arch:", runtime.GOARCH)
	LogMessage(LOG_INFO, "[INIT]", "Hostname:", GetHostname())
	LogMessage(LOG_INFO, "[INIT]", "User:", GetUsername())
	LogMessage(LOG_INFO, "[INIT]", "Current directory:", GetCurrentDirectory())
	LogMessage(LOG_INFO, "[INIT]", "Max file size scan:", fmt.Sprintf("%dMB", config.AdvancedParameters.MaxScanFilesize))
	LogMessage(LOG_INFO, "[INIT]", "Config file:", *pConfigPath)
	LogMessage(LOG_INFO, "[INIT]", "Fastfinder executable SHA256 checksum:", FileSHA256Sum(os.Args[0]))
	LogMessage(LOG_INFO, "[INIT]", "Configuration file SHA256 checksum:", FileSHA256Sum(*pConfigPath))

	if len(*pSfxPath) == 0 {
		// create mutex
		if _, err = CreateMutex("fastfinder"); err != nil {
			LogMessage(LOG_ERROR, "[ERROR]", "Only one instance or fastfinder can be launched:", err.Error())
			os.Exit(1)
		}

		// Retrieve current user permissions
		admin, elevated := CheckCurrentUserPermissions()
		if !admin && !elevated {
			LogMessage(LOG_INFO, "[WARNING] fastfinder is not running with fully elevated righs. Notice that the analysis will be partial and limited to the current user scope")
			if !*pHideWindow {
				time.Sleep(3 * time.Second)
			}
		}
	}

	// if yara rules mentionned - compile them
	if len(config.Input.Content.Yara) > 0 {
		LogMessage(LOG_INFO, "[INIT]", "Compiling Yara rules")
		compiler, err = LoadYaraRules(config.Input.Content.Yara, config.AdvancedParameters.YaraRC4Key)
		if err != nil {
			LogMessage(LOG_ERROR, err)
			os.Exit(1)
		}

		rules, err = CompileRules(compiler)
		if err != nil {
			LogMessage(LOG_ERROR, err)
			os.Exit(1)
		}

		LogMessage(LOG_INFO, "[INIT]", len(rules.GetRules()), "YARA rules compiled")
		for _, r := range rules.GetRules() {
			LogMessage(LOG_INFO, " | rule:", r.Identifier())
		}
	}

	// drives enumeration
	LogMessage(LOG_INFO, "[INIT]", "Enumerating drives")
	var basePaths []string
	drives, excludedPaths := EnumLogicalDrives()

	if len(drives) == 0 {
		LogMessage(LOG_ERROR, "[ERROR]", "Unable to find drives")
		os.Exit(1)
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
		LogMessage(LOG_ERROR, "[ERROR]", "No drive corresponding to your configuration drive type")
		os.Exit(1)
	} else {
		LogMessage(LOG_INFO, "[INIT]", "Looking for the following drives:")
		for _, p := range basePaths {
			LogMessage(LOG_INFO, "  |", p)
		}
	}

	if len(excludedPaths) > 0 {
		LogMessage(LOG_INFO, "[INFO]", "Excluding the following paths:")
		for _, p := range excludedPaths {
			LogMessage(LOG_INFO, "  |", p)
		}
	}

	if len(config.Input.Path) > 0 {
		LogMessage(LOG_INFO, "[INIT]", "Looking for the following paths patterns:")
		for _, p := range config.Input.Path {
			LogMessage(LOG_INFO, "  |", p)
		}
	}

	if runtime.GOOS != "windows" {
		sort.Slice(basePaths, func(i, j int) bool {
			return len(basePaths[i]) > len(basePaths[j])
		})
	}

	// start main routine
	for _, basePath := range basePaths {
		LogMessage(LOG_INFO, "[INFO]", "Enumerating files in", basePath)
		var matchContent []string
		var matchPattern []string

		// files listing
		files := *ListFilesRecursively(basePath, excludedPaths)
		if runtime.GOOS != "windows" {
			excludedPaths = append(excludedPaths, basePath)
		}

		// match file path
		if len(config.Input.Path) > 0 {
			LogMessage(LOG_INFO, "[INFO]", "Checking for paths matchs in", basePath)
			var pathRegexPatterns []*regexp2.Regexp
			for _, pattern := range config.Input.Path {
				re := regexp2.MustCompile(pattern, regexp2.IgnoreCase)
				pathRegexPatterns = append(pathRegexPatterns, re)
			}
			matchPattern = *PathsFinder(&files, pathRegexPatterns)
			if !config.Options.ContentMatchDependsOnPathMatch {
				for i := 0; i < len(matchPattern); i++ {
					LogMessage(LOG_INFO, "[ALERT]", "File path match on:", matchPattern[i])
				}
			}

		} else {
			matchPattern = files
		}

		// match content - contains
		if len(config.Input.Content.Grep) > 0 || len(config.Input.Content.Checksum) > 0 {
			LogMessage(LOG_INFO, "[INFO]", "Checking for content and checksum matchs in", basePath)
			if config.Options.ContentMatchDependsOnPathMatch {
				matchContent = *FindInFiles(&matchPattern, config.Input.Content.Grep, config.Input.Content.Checksum, config.AdvancedParameters.MaxScanFilesize, config.AdvancedParameters.CleanMemoryIfFileGreaterThanSize)
			} else {
				matchContent = *FindInFiles(&files, config.Input.Content.Grep, config.Input.Content.Checksum, config.AdvancedParameters.MaxScanFilesize, config.AdvancedParameters.CleanMemoryIfFileGreaterThanSize)
			}
		}

		// match content - yara
		if len(config.Input.Content.Yara) > 0 {
			if (len(matchPattern) == 0 && config.Options.ContentMatchDependsOnPathMatch) || (len(files) == 0 && !config.Options.ContentMatchDependsOnPathMatch) {
				LogMessage(LOG_INFO, "[INFO]", "Neither path nor pattern match. no file to scan with YARA.", basePath)
			} else {
				LogMessage(LOG_INFO, "[INFO]", "Checking for yara matchs in", basePath)
				if config.Options.ContentMatchDependsOnPathMatch {
					InitProgressbar(int64(len(matchPattern)))
					for i := 0; i < len(matchPattern); i++ {
						ProgressBarStep()
						if FileAnalyzeYaraMatch(matchPattern[i], rules) && (len(matchContent) == 0 || !Contains(matchContent, matchPattern[i])) {
							matchContent = append(matchContent, matchPattern[i])
						}
					}
				} else {
					InitProgressbar(int64(len(files)))
					for i := 0; i < len(files); i++ {
						ProgressBarStep()
						if FileAnalyzeYaraMatch(files[i], rules) && (len(matchContent) == 0 || !Contains(matchContent, files[i])) {
							matchContent = append(matchContent, files[i])
						}
					}
				}
			}
		}

		// also handle result if only match path pattern is set
		if len(config.Input.Content.Grep) == 0 && len(config.Input.Content.Checksum) == 0 && len(config.Input.Content.Yara) == 0 {
			matchContent = matchPattern
		}

		// handle false condition on ContentMatchDependsOnPathMatch options
		if len(config.Input.Path) > 0 && !config.Options.ContentMatchDependsOnPathMatch {
			for i := 0; i < len(matchPattern); i++ {
				if !Contains(matchContent, matchPattern[i]) {
					matchContent = append(matchContent, matchPattern[i])
				}
			}
		}

		// listing and copy matching files
		LogMessage(LOG_INFO, "[INFO]", "scan finished in", basePath)
		if len(matchContent) > 0 {
			LogMessage(LOG_INFO, "[INFO]", "Matching files: ")
			for i := 0; i < len(matchContent); i++ {
				LogMessage(LOG_INFO, "  |", matchContent[i])
			}

			if config.Output.CopyMatchingFiles {
				LogMessage(LOG_INFO, "[INFO]", "Copy all matching files")
				InitProgressbar(int64(len(matchPattern)))
				for i := 0; i < len(matchContent); i++ {
					ProgressBarStep()
					FileCopy(matchContent[i], config.Output.FilesCopyPath, config.Output.Base64Files)
				}
			}
		} else {
			LogMessage(LOG_INFO, "[INFO]", "No match found")
		}
	}
}
