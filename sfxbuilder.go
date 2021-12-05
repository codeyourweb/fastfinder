package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"io"
	"log"
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
		log.Fatal("[ERROR] ", err)
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
		log.Fatal("[ERROR] ", err)
	}

	fsFile, err := os.ReadFile(os.Args[0])
	if err != nil {
		log.Fatal("[ERROR] ", err)
	}

	r := bytes.NewReader(fsFile)
	_, err = io.Copy(zipFile, r)
	if err != nil {
		log.Fatal("[ERROR] ", err)
	}

	// embed yara rules
	for i := 0; i < len(configuration.Input.Content.Yara); i++ {
		fileName := filepath.Base(configuration.Input.Content.Yara[i])
		zipFile, err := archive.Create("fastfinder_resources/" + fileName)
		if err != nil {
			log.Fatal("[ERROR] ", err)
		}

		fsFile, err := os.ReadFile(configuration.Input.Content.Yara[i])
		if err != nil {
			log.Fatal("[ERROR] ", err)
		}

		r := bytes.NewReader(fsFile)
		_, err = io.Copy(zipFile, r)
		if err != nil {
			log.Fatal("[ERROR] ", err)
		}

		configuration.Input.Content.Yara[i] = "./fastfinder_resources/" + fileName
	}

	// embed configuration file
	zipFile, err = archive.Create("fastfinder_resources/configuration.yaml")
	if err != nil {
		log.Fatal("[ERROR] ", err)
	}
	d, err := yaml.Marshal(&configuration)
	if err != nil {
		log.Fatal("[ERROR] ", err)
	}

	r = bytes.NewReader(d)
	_, err = io.Copy(zipFile, r)
	if err != nil {
		log.Fatal("[ERROR] ", err)
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
		log.Fatal("[ERROR] ", err)
	}
	return buffer
}
