package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Configuration struct {
	Input              Input              `yaml:"input"`
	Options            Options            `yaml:"options"`
	Output             Output             `yaml:"output"`
	AdvancedParameters AdvancedParameters `yaml:"advancedparameters"`
	EventForwarding    ForwardingConfig   `yaml:"eventforwarding"`
}

type Input struct {
	Path        []string `yaml:"path"`
	DirectPaths []string `yaml:"-"`
	Content     Content  `yaml:"content"`
}

type Content struct {
	Grep     []string `yaml:"grep"`
	Yara     []string `yaml:"yara"`
	Checksum []string `yaml:"checksum"`
}

type Options struct {
	ContentMatchDependsOnPathMatch bool `yaml:"contentMatchDependsOnPathMatch"`
	FindInHardDrives               bool `yaml:"findInHardDrives"`
	FindInRemovableDrives          bool `yaml:"findInRemovableDrives"`
	FindInNetworkDrives            bool `yaml:"findInNetworkDrives"`
	FindInCDRomDrives              bool `yaml:"findInCDRomDrives"`
	FindInMemory                   bool `yaml:"findInMemory"`
}

type Output struct {
	Base64Files       bool   `yaml:"base64Files"`
	FilesCopyPath     string `yaml:"filesCopyPath"`
	CopyMatchingFiles bool   `yaml:"copyMatchingFiles"`
}

type AdvancedParameters struct {
	YaraRC4Key                       string `yaml:"yaraRC4Key"`
	MaxScanFilesize                  int    `yaml:"maxScanFilesize"`
	CleanMemoryIfFileGreaterThanSize int    `yaml:"cleanMemoryIfFileGreaterThanSize"`
}

func (c *Configuration) getConfiguration(configFile string) *Configuration {
	var yamlContent []byte
	var err error
	configFile = strings.TrimSpace(configFile)
	configBaseDir := ""

	if !IsValidUrl(configFile) {
		if absPath, err := filepath.Abs(configFile); err == nil {
			configFile = absPath
			configBaseDir = filepath.Dir(absPath)
		}
	}

	// configuration reading
	if IsValidUrl(configFile) {
		response, err := http.Get(configFile)
		if err != nil {
			LogFatal(fmt.Sprintf("Configuration file URL unreachable %v", err))
		}
		yamlContent, err = io.ReadAll(response.Body)
		if err != nil {
			LogFatal(fmt.Sprintf("Configuration file URL content unreadable %v", err))
		}
		response.Body.Close()
	} else {
		yamlContent, err = os.ReadFile(configFile)
		if err != nil {
			LogFatal(fmt.Sprintf("Configuration file reading error %v ", err))
		}
	}

	// ciphered yaml file
	if !bytes.Contains(yamlContent, []byte("input")) {
		yamlContent = RC4Cipher(yamlContent, BUILDER_RC4_KEY)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(yamlContent))
	decoder.KnownFields(true)
	err = decoder.Decode(c)

	if err != nil {
		LogFatal(fmt.Sprintf("%s - %v", configFile, err))
	}

	// check for specific user configuration params inconsistencies
	if len(c.Input.Path) == 0 || (len(c.Input.Content.Grep) == 0 && len(c.Input.Content.Yara) == 0 && len(c.Input.Content.Checksum) == 0) {
		c.Options.ContentMatchDependsOnPathMatch = false
	}

	if !c.Output.CopyMatchingFiles {
		c.Output.Base64Files = false
		c.Output.FilesCopyPath = ""
	}

	// check for missing advanced parameters
	if c.AdvancedParameters.MaxScanFilesize == 0 {
		c.AdvancedParameters.MaxScanFilesize = 2048
	}

	if c.AdvancedParameters.CleanMemoryIfFileGreaterThanSize == 0 {
		c.AdvancedParameters.CleanMemoryIfFileGreaterThanSize = 512
	}

	// parsing input paths
	environmentVariables := GetEnvironmentVariables()
	allPathsAreDirect := true
	var directPaths []string

	for i := 0; i < len(c.Input.Path); i++ {
		// replace environment variables
		for _, env := range environmentVariables {
			if strings.Contains(strings.ToLower(c.Input.Path[i]), "%"+strings.ToLower(env.Name)+"%") {
				c.Input.Path[i] = strings.Replace(c.Input.Path[i], "%"+env.Name+"%", env.Value, -1)
			}
		}

		// check for direct paths validity
		if allPathsAreDirect {
			rawPath := c.Input.Path[i]
			if strings.Contains(rawPath, "*") || strings.Contains(rawPath, "?") || (strings.HasPrefix(rawPath, "/") && strings.HasSuffix(rawPath, "/")) {
				allPathsAreDirect = false
			} else {
				if _, err := os.Stat(rawPath); err != nil {
					allPathsAreDirect = false
				} else {
					directPaths = append(directPaths, rawPath)
				}
			}
		}

		// handle regex and simple find strings
		if c.Input.Path[i][0] != '/' || c.Input.Path[i][len(c.Input.Path[i])-1] != '/' {
			c.Input.Path[i] = regexp.QuoteMeta(strings.ToLower(c.Input.Path[i]))
			// use regular expression ".+" for "*" search pattern
			if strings.Contains(strings.ToLower(c.Input.Path[i]), "\\*") {
				c.Input.Path[i] = strings.Replace(c.Input.Path[i], "\\*", "[^\\\\]+", -1)
			}

			if strings.Contains(strings.ToLower(c.Input.Path[i]), "\\\\[^\\\\]+") {
				c.Input.Path[i] = strings.Replace(c.Input.Path[i], "\\\\[^\\\\]+", "[^\\\\]+", -1)
			}

			if strings.Contains(strings.ToLower(c.Input.Path[i]), "\\?") {
				c.Input.Path[i] = strings.Replace(c.Input.Path[i], "\\?", ".", -1)
			}
		} else {
			c.Input.Path[i] = strings.Trim(c.Input.Path[i], "/")
		}

	}

	if allPathsAreDirect && len(directPaths) > 0 {
		c.Input.DirectPaths = directPaths
	}

	// normalize checksums
	for i := 0; i < len(c.Input.Content.Checksum); i++ {
		c.Input.Content.Checksum[i] = strings.ToLower(c.Input.Content.Checksum[i])
	}

	// normalize YARA paths relative to the configuration file directory
	if configBaseDir != "" {
		for i := 0; i < len(c.Input.Content.Yara); i++ {
			p := strings.TrimSpace(c.Input.Content.Yara[i])
			if len(p) == 0 || IsValidUrl(p) || filepath.IsAbs(p) {
				continue
			}
			c.Input.Content.Yara[i] = filepath.Clean(filepath.Join(configBaseDir, p))
		}
	}

	return c
}
