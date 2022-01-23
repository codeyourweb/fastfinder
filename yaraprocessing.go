package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/gen2brain/go-unarr"
	"github.com/h2non/filetype"
	"github.com/hillu/go-yara/v4"
)

// CompileYaraRules return *yara.Rules result of yara files compilation
func CompileYaraRules(yaraFiles []string, yaraRC4Key string) (rules *yara.Rules) {
	var compiler *yara.Compiler
	var err error

	LogMessage(LOG_VERBOSE, "(INIT)", "Compiling Yara rules")
	compiler, err = LoadYaraRules(yaraFiles, yaraRC4Key)
	if err != nil {
		LogMessage(LOG_ERROR, err)
		ExitProgram(1, !UIactive)
	}

	rules, err = CompileRules(compiler)
	if err != nil {
		LogMessage(LOG_ERROR, err)
		ExitProgram(1, !UIactive)
	}

	LogMessage(LOG_VERBOSE, "(INIT)", len(rules.GetRules()), "YARA rules compiled")
	for _, r := range rules.GetRules() {
		LogMessage(LOG_INFO, " | rule:", r.Identifier())
	}

	return rules
}

// PerformYaraScan use provided YARA rules and search for match in the given byte slice
func PerformYaraScan(data *[]byte, rules *yara.Rules) (yara.MatchRules, error) {
	result, err := yaraScan(*data, rules)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// PerformArchiveYaraScan try to decompress archive and YARA scan every file in it
func PerformArchiveYaraScan(path string, rules *yara.Rules) (matchs yara.MatchRules, err error) {
	var buffer [][]byte

	a, err := unarr.NewArchive(path)
	if err != nil {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return PerformYaraScan(&content, rules)
	}
	defer a.Close()

	list, err := a.List()
	if err != nil {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return PerformYaraScan(&content, rules)
	}
	for _, f := range list {
		err := a.EntryFor(f)
		if err != nil {
			return nil, err
		}

		data, err := a.ReadAll()
		if err != nil {
			return nil, err
		}

		buffer = append(buffer, data)
	}

	matchs, err = yaraScan(bytes.Join(buffer, []byte{}), rules)
	if err != nil {
		return nil, err
	}

	return matchs, nil
}

// LoadYaraRules compile yara rules from specified paths and return a pointer to the yara compiler
func LoadYaraRules(path []string, rc4key string) (compiler *yara.Compiler, err error) {
	compiler, err = yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize YARA compiler: %s", err.Error())
	}

	for _, dir := range EnumerateYaraInFolders(path) {
		var f []byte
		var err error

		if IsValidUrl(dir) {
			response, err := http.Get(dir)
			if err != nil {
				LogMessage(LOG_ERROR, "YARA file URL unreachable", dir, err)
				continue
			}
			f, err = ioutil.ReadAll(response.Body)
			if err != nil {
				LogMessage(LOG_ERROR, "YARA file URL content unreadable", dir, err)
				continue
			}
			response.Body.Close()
		} else {
			f, err = os.ReadFile(dir)
			if err != nil {
				LogMessage(LOG_ERROR, "(ERROR)", "Could not read rule file ", dir, err)
				continue
			}
		}

		if len(rc4key) > 0 && !bytes.Contains(f, []byte("rule")) && !bytes.Contains(f, []byte("condition")) {
			f = RC4Cipher(f, rc4key)
		}

		namespace := filepath.Base(dir)[:len(filepath.Base(dir))-4]
		if err = compiler.AddString(string(f), namespace); err != nil {
			LogMessage(LOG_ERROR, "(ERROR)", "Could not load rule file ", dir, err)
			continue
		}
	}

	return compiler, nil
}

// EnumerateYaraInFolders return a list of YARA rules path in the specified folders - if path already is a file or URL, it add it also
func EnumerateYaraInFolders(path []string) []string {
	var rulePaths []string

	for _, rulePath := range path {
		LogMessage(LOG_INFO, "Searching for YARA rules in", rulePath)
		rulePath = strings.TrimSpace(rulePath)

		fileInfo, err := os.Stat(rulePath)
		if err == nil {
			if fileInfo.IsDir() {
				paths, err := RetrivesFilesFromUserPath(rulePath, true, []string{".yar", ".yara"}, false)
				rulePaths = append(rulePaths, paths...)
				if err != nil {
					LogMessage(LOG_ERROR, "YARA file retrieve error found", rulePath, err)
					continue
				}
			} else {
				rulePaths = append(rulePaths, rulePath)
			}
		} else {
			if IsValidUrl(rulePath) {
				rulePaths = append(rulePaths, rulePath)
			}
		}
	}

	return rulePaths
}

// CompileRules try to compile every rules from the given compiler
func CompileRules(compiler *yara.Compiler) (rules *yara.Rules, err error) {
	rules, err = compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("failed to compile rules: %s", err.Error())
	}

	return rules, err
}

// yaraScan use libyara to scan the specified content with a compiled rule
func yaraScan(content []byte, rules *yara.Rules) (match yara.MatchRules, err error) {
	sc, _ := yara.NewScanner(rules)
	var m yara.MatchRules
	err = sc.SetCallback(&m).ScanMem(content)
	return m, err
}

// FileAnalyzeYaraMatch use yara to scan the specified file and return if it match to compiled rules or not
func FileAnalyzeYaraMatch(path string, rules *yara.Rules, maxFileSizeScan int, cleanMemoryIfSizeGreaterThan int) bool {
	var err error
	var content []byte
	var result yara.MatchRules

	if _, err = os.Stat(path); err != nil {
		LogMessage(LOG_ERROR, "(ERROR)", path, err)
		return false
	}

	// read file content
	content, err = os.ReadFile(path)
	if err != nil {
		LogMessage(LOG_ERROR, "(ERROR)", path, err)
		return false
	}

	filetype, err := filetype.Match(content)
	if err != nil {
		LogMessage(LOG_ERROR, "(ERROR)", path, err)
		return false
	}

	// cleaning memory if file size is greater than 512Mb
	if len(content) > 1024*1024*cleanMemoryIfSizeGreaterThan {
		defer debug.FreeOSMemory()
	}

	// cancel analysis if file size is greater than 2Gb
	if len(content) > 1024*1024*2048 {
		LogMessage(LOG_ERROR, fmt.Sprintf("File size is greater than %dMb, skipping", maxFileSizeScan), path)
		return false
	}

	// archive or other file format scan
	if Contains([]string{"application/x-tar", "application/x-7z-compressed", "application/zip", "application/vnd.rar"}, filetype.MIME.Value) {
		result, err = PerformArchiveYaraScan(path, rules)
		if err != nil {
			LogMessage(LOG_ERROR, "(ERROR)", "Error performing yara scan on", path, err)
			return false
		}
	} else {
		result, err = PerformYaraScan(&content, rules)
		if err != nil {
			LogMessage(LOG_ERROR, "(ERROR)", "Error performing yara scan on", path, err)
			return false
		}
	}

	// output rules matchs
	for i := 0; i < len(result); i++ {
		LogMessage(LOG_ALERT, "(ALERT)", "YARA match:")
		LogMessage(LOG_ALERT, " | path:", path)
		LogMessage(LOG_ALERT, " | rule namespace:", result[i].Namespace)
		LogMessage(LOG_ALERT, " | rule name:", result[i].Rule)
	}

	return len(result) > 0
}
