package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// BuildSFX creates a self-extracting rar zip and embed the fastfinder executable / configuration file / yara rules
func BuildSFX(configuration Configuration, outputSfxExe string, logLevel int, logFileLocation string, noAdvUI bool, hideWindow bool) {
	// compress inputDirectory into archive
	archive := fastfinderResourcesCompress(configuration, logLevel, logFileLocation, noAdvUI, hideWindow)

	file, err := os.Create(outputSfxExe)
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) %v", err))
	}

	defer file.Close()

	// pack sfx binary and customized archive together
	file.Write(sfxBinary)
	file.Write(archive.Bytes())
}

// fastfinderResourcesCompress compress every package file into the zip archive
func fastfinderResourcesCompress(configuration Configuration, logLevel int, logFileLocation string, noAdvUI bool, hideWindow bool) bytes.Buffer {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)

	// embed fastfinder executable
	exeName := "fastfinder"
	if runtime.GOOS == "windows" {
		exeName += ".exe"
	}
	zipFile, err := archive.Create(exeName)
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) %v", err))
	}

	fsFile, err := os.ReadFile(os.Args[0])
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) %v", err))
	}

	r := bytes.NewReader(fsFile)
	_, err = io.Copy(zipFile, r)
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) %v", err))
	}

	// embed yara rules
	for i := 0; i < len(configuration.Input.Content.Yara); i++ {
		var fileName string
		var fsFile []byte

		if IsValidUrl(configuration.Input.Content.Yara[i]) {
			response, err := http.Get(configuration.Input.Content.Yara[i])
			if err != nil {
				LogMessage(LOG_ERROR, "YARA file URL unreachable", configuration.Input.Content.Yara[i], err)
			}
			fsFile, err = ioutil.ReadAll(response.Body)
			if err != nil {
				LogMessage(LOG_ERROR, "YARA file URL content unreadable", configuration.Input.Content.Yara[i], err)
			}
			response.Body.Close()
			fileName = filepath.Base(configuration.Input.Content.Yara[i])[:len(filepath.Base(configuration.Input.Content.Yara[i]))-4]
			if !strings.HasSuffix(fileName, ".yar") {
				fileName += ".yar"
			}

		} else {
			fileName = filepath.Base(configuration.Input.Content.Yara[i])
			fsFile, err = os.ReadFile(configuration.Input.Content.Yara[i])

			if err != nil {
				LogFatal(fmt.Sprintf("(ERROR) %v", err))
			}
		}

		zipFile, err := archive.Create("fastfinder_resources/" + fileName)
		if err != nil {
			LogFatal(fmt.Sprintf("(ERROR) %v", err))
		}

		// cipher rules
		if configuration.AdvancedParameters.YaraRC4Key != "" {
			fsFile = RC4Cipher(fsFile, configuration.AdvancedParameters.YaraRC4Key)
		}

		r := bytes.NewReader(fsFile)
		_, err = io.Copy(zipFile, r)
		if err != nil {
			LogFatal(fmt.Sprintf("(ERROR) %v", err))
		}

		configuration.Input.Content.Yara[i] = "'./fastfinder_resources/" + fileName + "'"

	}

	// embed configuration file
	zipFile, err = archive.Create("fastfinder_resources/configuration.yaml")
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) %v", err))
	}
	d, err := yaml.Marshal(&configuration)
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) %v", err))
	}

	// cipher configuration file
	d = RC4Cipher(d, BUILDER_RC4_KEY)

	r = bytes.NewReader(d)
	_, err = io.Copy(zipFile, r)
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) %v", err))
	}

	// sfx exec instructions
	var sfxcomment = "the comment below contains sfx script commands\r\n\r\n" +
		"Path=%TEMP%\r\n" +
		"Setup=./" + exeName + " -c fastfinder_resources/configuration.yaml"

	// propagate loglevel param
	sfxcomment += fmt.Sprintf(" -l %d", logLevel)

	// propagage advanced UI param
	if noAdvUI {
		sfxcomment += " -u"
	}

	// output log file
	if len(logFileLocation) > 0 {
		//sfxcomment += " -o \"" + logFileLocation + "\""
		sfxcomment += fmt.Sprintf(" -o %s", logFileLocation)
	}

	if hideWindow {
		sfxcomment += " -n"
		sfxcomment += "\r\n" +
			"Silent=1"
	}

	archive.SetComment(sfxcomment)

	if err != nil {
		return buffer
	}
	err = archive.Close()

	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) %v", err))
	}
	return buffer
}
