package main

import (
	"io/ioutil"
	"log"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Configuration struct {
	Input   Input   `yaml:"input"`
	Options Options `yaml:"options"`
	Output  Output  `yaml:"output"`
}

type Input struct {
	Path    []string `yaml:"path"`
	Content Content  `yaml:"content"`
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
}

type Output struct {
	Base64Files   bool   `yaml:"base64Files"`
	FilesCopyPath string `yaml:"filesCopyPath"`
}

func (c *Configuration) getConfiguration(configFile string) *Configuration {

	yamlFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Configuration file reading error #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Configuration file parsing error: %v", err)
	}

	environmentVariables := getEnvironmentVariables()

	for i := 0; i < len(c.Input.Path); i++ {
		// replace environment variables
		for _, env := range environmentVariables {
			if strings.Contains(strings.ToLower(c.Input.Path[i]), "%"+strings.ToLower(env.Name)+"%") {
				c.Input.Path[i] = strings.Replace(c.Input.Path[i], "%"+env.Name+"%", env.Value, -1)
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

	// normalize checksums
	for i := 0; i < len(c.Input.Content.Checksum); i++ {
		c.Input.Content.Checksum[i] = strings.ToLower(c.Input.Content.Checksum[i])
	}

	return c
}
