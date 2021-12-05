// #cgo !yara_no_pkg_config,!yara_static  pkg-config: yara
// #cgo !yara_no_pkg_config,yara_static   pkg-config: --static yara
// #cgo yara_no_pkg_config                LDFLAGS:    -lyara
// compile: go build -tags yara_static -a -ldflags '-s -w -extldflags "-static"' .
package main

import (
	"log"
	"os"

	"github.com/akamensky/argparse"
	"github.com/dlclark/regexp2"
	"github.com/hillu/go-yara/v4"
)

func main() {
	var compiler *yara.Compiler
	var rules *yara.Rules
	var err error

	if _, err = CreateMutex("fastfinder"); err != nil {
		LogMessage(LOG_ERROR, "[ERROR]", "Only one instance or fastfinder can be launched")
		os.Exit(1)
	}

	// parse configuration file
	parser := argparse.NewParser("fastfinder", "Incident Response - Fast suspicious file finder")
	configPath := parser.String("c", "configuration", &argparse.Options{Required: true, Default: "configuration.yaml", Help: "Fastfind configuration file"})
	sfxPath := parser.String("b", "build", &argparse.Options{Required: false, Help: "Output a standalone package with configuration and rules in a single binary"})
	outLogPath := parser.String("o", "output", &argparse.Options{Required: false, Help: "Save fastfinder logs in the specified file"})
	hideWindow := parser.Flag("n", "nowindow", &argparse.Options{Required: false, Help: "Hide fastfinder window"})

	err = parser.Parse(os.Args)
	if err != nil {
		log.Fatal(parser.Usage(err))
	}

	var config Configuration
	config.getConfiguration(*configPath)
	if config.Output.FilesCopyPath != "" {
		config.Output.FilesCopyPath = "./"
	}

	// window hidden
	if *hideWindow {
		HideConsoleWindow()
	}

	// init file logging
	if len(*outLogPath) > 0 {
		StdoutToLogFile(*outLogPath)
		StderrToLogFile(*outLogPath)
	}

	// check for input configuration
	if len(config.Input.Path) == 0 && len(config.Input.Content.Grep) == 0 && len(config.Input.Content.Yara) == 0 {
		LogMessage(LOG_ERROR, "[ERROR]", "Input parameters empty - cannot find any item")
		os.Exit(1)
	}

	// sfx building option
	if len(*sfxPath) > 0 {
		BuildSFX(config, *sfxPath, *outLogPath, *hideWindow)
		LogMessage(LOG_INFO, "[INFO]", "package generated successfully at", *sfxPath)
		os.Exit(0)
	}

	// if yara rules mentionned - compile them
	if len(config.Input.Content.Yara) > 0 {
		LogMessage(LOG_INFO, "[INIT]", "Compiling Yara rules")
		compiler, err = LoadYaraRules(config.Input.Content.Yara)
		if err != nil {
			LogMessage(LOG_ERROR, err)
			os.Exit(1)
		}

		rules, err = CompileRules(compiler)
		if err != nil {
			LogMessage(LOG_ERROR, err)
			os.Exit(1)
		}
	}

	// drives enumeration
	LogMessage(LOG_INFO, "[INIT]", "Enumerating drives")
	var basePaths []string
	drives := EnumLogicalDrives()

	if len(drives) == 0 {
		LogMessage(LOG_ERROR, "[ERROR]", "Unable to find drives")
		os.Exit(1)
	}
	for _, drive := range drives {
		if (drive.Type == DRIVE_REMOVABLE && config.Options.FindInRemovableDrives) ||
			(drive.Type == DRIVE_FIXED && config.Options.FindInHardDrives) ||
			(drive.Type == DRIVE_REMOTE && config.Options.FindInNetworkDrives) ||
			(drive.Type == DRIVE_CDROM && config.Options.FindInCDRomDrives) {
			basePaths = append(basePaths, drive.Name+":\\")
		}
	}

	if len(basePaths) == 0 {
		LogMessage(LOG_ERROR, "[ERROR]", "No drive corresponding to your configuration drive type")
		os.Exit(1)
	} else {
		LogMessage(LOG_INFO, "[INIT]", "Looking for the following drives", basePaths)
	}

	LogMessage(LOG_INFO, "[INIT]", "Looking for the following paths patterns:")
	for _, p := range config.Input.Path {
		LogMessage(LOG_INFO, "  |", p)
	}

	// start main routine
	LogMessage(LOG_INFO, "[INFO]", "Enumerating files")
	for _, basePath := range basePaths {
		LogMessage(LOG_INFO, "[INFO]", "Looking for files in", basePath)
		var matchContent *[]string
		var matchPattern *[]string

		// files listing
		files := ListFilesRecursively(basePath)

		// match file path
		if len(config.Input.Path) > 0 {
			LogMessage(LOG_INFO, "[INFO]", "Checking for paths matchs in", basePath)
			var pathRegexPatterns []*regexp2.Regexp
			for _, pattern := range config.Input.Path {
				re := regexp2.MustCompile(pattern, regexp2.IgnoreCase)
				pathRegexPatterns = append(pathRegexPatterns, re)
			}
			matchPattern = PathsFinder(files, pathRegexPatterns)
			if !config.Options.ContentMatchDependsOnPathMatch {
				for _, file := range *matchPattern {
					LogMessage(LOG_INFO, "[ALERT]", "File match on", file)
				}
			}

		} else {
			matchPattern = files
		}

		// match content - contains
		if len(config.Input.Content.Grep) > 0 || len(config.Input.Content.Checksum) > 0 {
			LogMessage(LOG_INFO, "[INFO]", "Checking for content and checksum matchs in", basePath)
			if config.Options.ContentMatchDependsOnPathMatch {
				matchContent = FindInFiles(matchPattern, config.Input.Content.Grep, config.Input.Content.Checksum)
			} else {
				matchContent = FindInFiles(files, config.Input.Content.Grep, config.Input.Content.Checksum)
			}
		}

		// match content - yara
		if len(config.Input.Content.Yara) > 0 {
			LogMessage(LOG_INFO, "[INFO]", "Checking for yara matchs in", basePath)
			if config.Options.ContentMatchDependsOnPathMatch {
				for _, file := range *matchPattern {
					if FileAnalyzeYaraMatch(file, rules) && !Contains(*matchContent, file) {
						LogMessage(LOG_INFO, "[ALERT]", "File match on", file)
						*matchContent = append(*matchContent, file)
					}
				}
			} else {
				for _, file := range *files {
					if FileAnalyzeYaraMatch(file, rules) && !Contains(*matchContent, file) {
						LogMessage(LOG_INFO, "[ALERT]", "File match on", file)
						*matchContent = append(*matchContent, file)
					}
				}
			}
		}

		// also handle result if only match path pattern is set
		if len(config.Input.Content.Grep) == 0 && len(config.Input.Content.Checksum) == 0 && len(config.Input.Content.Yara) == 0 {
			matchContent = matchPattern
		}

		// handle false condition on ContentMatchDependsOnPathMatch options
		if !config.Options.ContentMatchDependsOnPathMatch {
			for _, p := range *matchPattern {
				if !Contains(*matchContent, p) {
					*matchContent = append(*matchContent, p)
				}
			}
		}

		// copy matching files
		LogMessage(LOG_INFO, "[INFO]", "Copy all matching files")
		for _, f := range *matchContent {
			FileCopy(f, config.Output.FilesCopyPath, config.Output.Base64Files)
		}
	}
}
