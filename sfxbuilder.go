package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed resources/winrar_sfx.exe
var sfxBinary []byte

// BuildSFX creates a self-extracting rar zip and embed the fastfinder executable / configuration file / yara rules
func BuildSFX(configuration Configuration, outputSfxExe, logFileLocation string, hideWindow bool) {
	// compress inputDirectory into archive
	archive := fastfinderResourcesCompress(configuration, logFileLocation, hideWindow)

	file, err := os.Create(outputSfxExe)
	if err != nil {
		log.Fatal("{ERROR} ", err)
	}

	defer file.Close()

	// pack sfx binary and customized archive together
	file.Write(sfxBinary)
	file.Write(archive.Bytes())
}

// fastfinderResourcesCompress compress every package file into the zip archive
func fastfinderResourcesCompress(configuration Configuration, logFileLocation string, hideWindow bool) bytes.Buffer {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)

	// embed fastfinder.exe executable
	zipFile, err := archive.Create("fastfinder.exe")
	if err != nil {
		log.Fatal("{ERROR} ", err)
	}

	fsFile, err := os.ReadFile(os.Args[0])
	if err != nil {
		log.Fatal("{ERROR} ", err)
	}

	r := bytes.NewReader(fsFile)
	_, err = io.Copy(zipFile, r)
	if err != nil {
		log.Fatal("{ERROR} ", err)
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

		} else {
			fileName = filepath.Base(configuration.Input.Content.Yara[i])
			fsFile, err = os.ReadFile(configuration.Input.Content.Yara[i])

			if err != nil {
				log.Fatal("{ERROR} ", err)
			}
		}

		zipFile, err := archive.Create("fastfinder_resources/" + fileName)
		if err != nil {
			log.Fatal("{ERROR} ", err)
		}

		// cipher rules
		if configuration.AdvancedParameters.YaraRC4Key != "" {
			fsFile = RC4Cipher(fsFile, configuration.AdvancedParameters.YaraRC4Key)
		}

		r := bytes.NewReader(fsFile)
		_, err = io.Copy(zipFile, r)
		if err != nil {
			log.Fatal("{ERROR} ", err)
		}

		configuration.Input.Content.Yara[i] = "./fastfinder_resources/" + fileName

	}

	// embed configuration file
	zipFile, err = archive.Create("fastfinder_resources/configuration.yaml")
	if err != nil {
		log.Fatal("{ERROR} ", err)
	}
	d, err := yaml.Marshal(&configuration)
	if err != nil {
		log.Fatal("{ERROR} ", err)
	}

	// cipher configuration file
	d = RC4Cipher(d, BUILDER_RC4_KEY)

	r = bytes.NewReader(d)
	_, err = io.Copy(zipFile, r)
	if err != nil {
		log.Fatal("{ERROR} ", err)
	}

	// sfx exec instructions
	var sfxcomment = "the comment below contains sfx script commands\r\n\r\n" +
		"Path=%TEMP%\r\n" +
		"Setup=fastfinder.exe -c fastfinder_resources/configuration.yaml"

	// output log file
	if len(logFileLocation) > 0 {
		sfxcomment += " -o \"" + logFileLocation + "\""
	}

	if hideWindow {
		sfxcomment += " -n"
	}

	// silent deploy
	sfxcomment += "\r\n" +
		"Silent=1\r\n" +
		"Overwrite=1"

	archive.SetComment(sfxcomment)

	if err != nil {
		return buffer
	}
	err = archive.Close()

	if err != nil {
		log.Fatal("{ERROR} ", err)
	}
	return buffer
}
