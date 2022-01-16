package main

import (
	"crypto/rc4"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/user"
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

// RenderFastfinderLogo is a (useless) function displaying fastfinder logo as ascii art
func RenderFastfinderLogo() string {
	txtLogo := "  ___       __  ___  ___         __   ___  __     " + LineBreak
	txtLogo += " |__   /\\  /__`  |  |__  | |\\ | |  \\ |__  |__) " + LineBreak
	txtLogo += " |    /~~\\ .__/  |  |    | | \\| |__/ |___ |  \\ " + LineBreak
	txtLogo += "                                                  " + LineBreak
	txtLogo += "  2021-2022 | Jean-Pierre GARNIER | @codeyourweb  " + LineBreak
	txtLogo += "  https://github.com/codeyourweb/fastfinder       " + LineBreak
	return txtLogo
}

// RenderFastfinderVersion returns program and YARA version
func RenderFastfinderVersion() string {
	return "Fastfinder version " + FASTFINDER_VERSION + " with embedded YARA version " + YARA_VERSION
}

// ExitProgram close file log handles and exit the program
func ExitProgram(code int, noWindow bool) {
	if !noWindow {
		message := "Press Ctrl+C to exit"
		if AppStarted {
			message = "[yellow]" + message
		}
		LogMessage(LOG_EXIT, message)
		fmt.Scanln()
		fmt.Print("\n\n")
	}

	if loggingFile != nil {
		loggingFile.Close()
	}

	os.Exit(code)
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

// RetrivesFilesFromUserPath return a []string of available files from specified path (includeFileExtensions is available only if listFiles is true)
func RetrivesFilesFromUserPath(path string, listFiles bool, includeFileExtensions []string, recursive bool) ([]string, error) {
	var p []string

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return []string{}, errors.New("Input file not found")
	}

	if !info.IsDir() {
		p = append(p, path)
	} else {
		if !recursive {
			files, err := os.ReadDir(path)
			if err != nil {
				return []string{}, err
			}
			for _, f := range files {
				if !(f.IsDir() == listFiles) && (len(includeFileExtensions) == 0 || Contains(includeFileExtensions, filepath.Ext(f.Name()))) {
					p = append(p, path+string(os.PathSeparator)+f.Name())
				}
			}
		} else {
			err := filepath.Walk(path, func(walk string, info os.FileInfo, err error) error {
				if err != nil {
					LogMessage(LOG_ERROR, "(ERROR)", err)
				}

				if err == nil && !(info.IsDir() == listFiles) && (len(includeFileExtensions) == 0 || Contains(includeFileExtensions, filepath.Ext(walk))) {
					p = append(p, walk)
				}

				return nil
			})

			if err != nil {
				LogMessage(LOG_ERROR, "(ERROR)", err)
			}
		}
	}

	return p, nil
}

// ListFilesRecursively returns a list of files in the specified path and its subdirectories
func ListFilesRecursively(path string, excludedPaths []string) *[]string {
	var files []string

	err := filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			LogMessage(LOG_ERROR, "(ERROR)", err)
			return filepath.SkipDir
		}

		if !f.IsDir() {
			for _, excludedPath := range excludedPaths {
				if len(excludedPath) > 1 && strings.HasPrefix(path, excludedPath) && len(path) > len(excludedPath) {
					LogMessage(LOG_INFO, "(INFO)", "Skipping dir", path)
					return filepath.SkipDir
				}
			}

			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		LogMessage(LOG_ERROR, "(ERROR)", err)
	}

	return &files
}

// FileCopy copy the specified file from src to dst path, and eventually encode its content to base64
func FileCopy(src, dst string, base64Encode bool) {
	dst += filepath.Base(src) + ".fastfinder"
	srcFile, err := os.Open(src)
	if err != nil {
		LogFatal(fmt.Sprintf("%v", err))
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		LogFatal(fmt.Sprintf("%v", err))
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
		LogFatal(fmt.Sprintf("%v", err))
	}
}

// Contains checks if a string is contained in a slice of strings
func Contains(s []string, str string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == str {
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

// GetHostname returns the hostname of the current machine
func GetHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}

	return name
}

// GetUsername returns the current user name
func GetUsername() string {
	user, err := user.Current()
	if err != nil {
		return ""
	}

	return user.Username
}

// GetCurrentDirectory returns the current directory
func GetCurrentDirectory() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	return dir
}

// Get SHA256 checksum of the specified file
func FileSHA256Sum(path string) string {
	file, err := os.Open(path)

	if err != nil {
		panic(err)
	}

	defer file.Close()

	hash := sha256.New()
	_, err = io.Copy(hash, file)

	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

// RC4Cipher is used on Yara ciphered rules
func RC4Cipher(content []byte, key string) []byte {
	c, err := rc4.NewCipher([]byte(key))
	if err != nil {
		LogFatal(fmt.Sprintf("(ERROR) %v", err))
	}

	c.XORKeyStream(content, content)

	return content
}
