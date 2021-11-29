// #cgo !yara_no_pkg_config,!yara_static  pkg-config: yara
// #cgo !yara_no_pkg_config,yara_static   pkg-config: --static yara
// #cgo yara_no_pkg_config                LDFLAGS:    -lyara
// compile: go build -tags yara_static -a -ldflags '-s -w -extldflags "-static"' .
package main

import (
	"log"
	"os"

	"github.com/akamensky/argparse"
	"github.com/hillu/go-yara/v4"
)

func main() {
	var compiler *yara.Compiler
	var rules *yara.Rules
	var err error

	if _, err = CreateMutex("fastfinder"); err != nil {
		logMessage(LOG_ERROR, "[ERROR]", "Only one instance or fastfinder can be launched")
		os.Exit(1)
	}

	// parse configuration file
	parser := argparse.NewParser("fastfinder", "Incident Response - Fast suspicious file finder")
	configPath := parser.String("c", "configuration", &argparse.Options{Required: true, Help: "fastfind configuration file"})
	err = parser.Parse(os.Args)
	if err != nil {
		log.Fatal(parser.Usage(err))
	}

	var config Configuration
	config.getConfiguration(*configPath)
	if config.Output.FilesCopyPath != "" {
		config.Output.FilesCopyPath = "./"
	}

	if len(config.Input.Path) == 0 && len(config.Input.Content.Grep) == 0 && len(config.Input.Content.Yara) == 0 {
		logMessage(LOG_ERROR, "[ERROR]", "Input parameters empty - cannot find any item")
		os.Exit(1)
	}

	// if yara rules mentionned - compile them
	if len(config.Input.Content.Yara) > 0 {
		logMessage(LOG_INFO, "[INIT]", "Compiling Yara rules")
		compiler, err = LoadYaraRules(config.Input.Content.Yara)
		if err != nil {
			logMessage(LOG_ERROR, err)
			os.Exit(1)
		}

		rules, err = CompileRules(compiler)
		if err != nil {
			logMessage(LOG_ERROR, err)
			os.Exit(1)
		}
	}

	// drives enumeration
	logMessage(LOG_INFO, "[INIT]", "Enumerating drives")
	var basePaths []string
	drives := enumLogicalDrives()

	if len(drives) == 0 {
		logMessage(LOG_ERROR, "[ERROR]", "Unable to find drives")
		os.Exit(1)
	}
	for _, drive := range drives {
		if (drive.Type == DRIVE_REMOVABLE && config.Options.FindInRemovableDrives) ||
			(drive.Type == DRIVE_FIXED && config.Options.FindInHardDrives) ||
			(drive.Type == DRIVE_REMOTE && config.Options.FindInNetworkDrives) {
			basePaths = append(basePaths, drive.Name+":\\")
		}
	}

	if len(basePaths) == 0 {
		logMessage(LOG_ERROR, "[ERROR]", "No drive corresponding to your configuration drive type")
		os.Exit(1)
	} else {
		logMessage(LOG_INFO, "[INFO]", "Looking for the following drives", basePaths)
	}

	logMessage(LOG_INFO, "[INFO]", "Looking for the following paths patterns:")
	for _, p := range config.Input.Path {
		logMessage(LOG_INFO, p)
	}

	// look for file matchs
	logMessage(LOG_INFO, "[INIT]", "Enumerating files")
	for _, basePath := range basePaths {
		logMessage(LOG_INFO, "[INFO]", "Looking for files in", basePath)
		var matchContent []string
		// files listing
		files := listFilesRecursively(basePath)

		// match file path
		var matchPattern []string
		if len(config.Input.Path) > 0 {
			matchPattern = pathsFinder(files, config.Input.Path)
		} else {
			matchPattern = files
		}

		// match content - contains
		if len(config.Input.Content.Grep) > 0 {
			matchContent = findInFiles(matchPattern, config.Input.Content.Grep)
		}

		// match content - yara
		if len(config.Input.Content.Yara) > 0 {
			for _, file := range matchPattern {
				if FileAnalyzeYaraMatch(file, rules) && !contains(matchContent, file) {
					matchContent = append(matchContent, file)
				}
			}
		}

		// output matched files and copy
		for _, f := range matchContent {
			logMessage(LOG_INFO, "[INFO]", "File match on", f)
			FileCopy(f, config.Output.FilesCopyPath, config.Output.Base64Files)
		}
	}

}
