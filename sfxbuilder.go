package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// BuildSFX creates a self-extracting rar zip and embed the fastfinder executable / configuration file / yara rules
func BuildSFX(configPath string, outputSfxExe string, logLevel int, noAdvUI bool) {
	var configuration Configuration

	yamlContent, err := os.ReadFile(configPath)
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) Reading config for SFX: %v", err))
	}
	// We handle optional cipher
	if !bytes.Contains(yamlContent, []byte("input")) {
		yamlContent = RC4Cipher(yamlContent, ">\u00D5\u00B0\u00AAKb{\u00A1\u00A7\u00CCB$lM\u00D5\u00B19l.t\u00F2\u00D1\u00E9\u00A6\u00D8\u00BF") // Using the constant value manually or via reference if public
	}

	err = yaml.Unmarshal(yamlContent, &configuration)
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) Parsing config for SFX: %v", err))
	}

	// Resolve YARA paths relative to configuration file (Critical to find files during build)
	configBaseDir := filepath.Dir(configPath)
	if configBaseDir != "" && configBaseDir != "." {
		for i := 0; i < len(configuration.Input.Content.Yara); i++ {
			p := strings.TrimSpace(configuration.Input.Content.Yara[i])
			if len(p) == 0 || IsValidUrl(p) || filepath.IsAbs(p) {
				continue
			}
			configuration.Input.Content.Yara[i] = filepath.Clean(filepath.Join(configBaseDir, p))
		}
	}

	// compress inputDirectory into archive
	archive := fastfinderResourcesCompress(configuration, logLevel, noAdvUI)

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
func fastfinderResourcesCompress(configuration Configuration, logLevel int, noAdvUI bool) bytes.Buffer {
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
	configuration.Input.Content.Yara = EnumerateYaraInFolders(configuration.Input.Content.Yara)
	for i := 0; i < len(configuration.Input.Content.Yara); i++ {
		var fileName string
		var fsFile []byte

		if IsValidUrl(configuration.Input.Content.Yara[i]) {
			response, err := http.Get(configuration.Input.Content.Yara[i])
			if err != nil {
				LogMessage(LOG_ERROR, "YARA file URL unreachable", configuration.Input.Content.Yara[i], err)
			}
			fsFile, err = io.ReadAll(response.Body)
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

		configuration.Input.Content.Yara[i] = fileName

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
		"Path=" + tempFolder + "\r\n" +
		"Setup=" + exeName + " -c " + "fastfinder_resources/configuration.yaml"

	// propagate loglevel param
	sfxcomment += fmt.Sprintf(" -v %d", logLevel)

	// propagage advanced UI param
	if noAdvUI {
		sfxcomment += " -u"
	}

	archive.SetComment(sfxcomment)

	err = archive.Close()

	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) %v", err))
	}
	return buffer
}
