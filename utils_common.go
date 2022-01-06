package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Env struct {
	Name  string
	Value string
}

type DriveInfo struct {
	Name string
	Type uint32
}

const (
	DRIVE_UNKNOWN     = 0
	DRIVE_NO_ROOT_DIR = 1
	DRIVE_REMOVABLE   = 2
	DRIVE_FIXED       = 3
	DRIVE_REMOTE      = 4
	DRIVE_CDROM       = 5
	DRIVE_RAMDISK     = 6
)

// PrintFastfinderLogo is a (useless) function displaying fastfinder logo as ascii art
func PrintFastfinderLogo() {
	fmt.Println("==================================================")
	fmt.Println("  ___       __  ___  ___         __   ___  __     ")
	fmt.Println(" |__   /\\  /__`  |  |__  | |\\ | |  \\ |__  |__) ")
	fmt.Println(" |    /~~\\ .__/  |  |    | | \\| |__/ |___ |  \\ ")
	fmt.Println("                                                  ")
	fmt.Println("  2021-2022 | Jean-Pierre GARNIER | @codeyourweb  ")
	fmt.Println("  https://github.com/codeyourweb/fastfinder       ")
	fmt.Println("==================================================")
}

// GetEnvironmentVariables return a list of environment variables in []Env slice
func GetEnvironmentVariables() (environmentVariables []Env) {
	for _, item := range os.Environ() {
		envPair := strings.SplitN(item, "=", 2)
		env := Env{
			Name:  envPair[0],
			Value: envPair[1],
		}
		environmentVariables = append(environmentVariables, env)
	}

	return environmentVariables
}

// ListFilesRecursively returns a list of files in the specified path and its subdirectories
func ListFilesRecursively(path string, excludedPaths []string) *[]string {
	var files []string

	err := filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			LogMessage(LOG_ERROR, "[ERROR]", err)
			return filepath.SkipDir
		}

		if !f.IsDir() {
			for _, excludedPath := range excludedPaths {
				if len(excludedPath) > 1 && strings.HasPrefix(path, excludedPath) && len(path) > len(excludedPath) {
					LogMessage(LOG_INFO, "[INFO]", "Skipping dir", path)
					return filepath.SkipDir
				}
			}

			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		LogMessage(LOG_ERROR, "[ERROR]", err)
	}

	return &files
}

// FileCopy copy the specified file from src to dst path, and eventually encode its content to base64
func FileCopy(src, dst string, base64Encode bool) {
	dst += filepath.Base(src) + ".fastfinder"
	srcFile, err := os.Open(src)
	if err != nil {
		log.Fatal(err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		log.Fatal(err)
	}
	defer dstFile.Close()

	if base64Encode {
		encoder := base64.NewEncoder(base64.StdEncoding, dstFile)
		defer encoder.Close()

		_, err = io.Copy(encoder, srcFile)
	} else {
		_, err = io.Copy(dstFile, srcFile)
	}

	if err != nil {
		log.Fatal(err)
	}
}

// Contains checks if a string is contained in a slice of strings
func Contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

// IsValidUrl tests a string to determine if it is a well-structured url or not.
func IsValidUrl(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}
