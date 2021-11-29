package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/gen2brain/go-unarr"
	"github.com/h2non/filetype"
	"github.com/hillu/go-yara/v4"
)

// PerformYaraScan use provided YARA rules and search for match in the given byte slice
func PerformYaraScan(data *[]byte, rules *yara.Rules) yara.MatchRules {
	result, err := YaraScan(*data, rules)
	if err != nil {
		logMessage(LOG_ERROR, "[ERROR]", err)
	}

	return result
}

// PerformArchiveYaraScan try to decompress archive and YARA scan every file in it
func PerformArchiveYaraScan(path string, rules *yara.Rules) (matchs yara.MatchRules) {
	var buffer [][]byte

	a, err := unarr.NewArchive(path)
	if err != nil {
		logMessage(LOG_ERROR, "[ERROR]", err)
		return matchs
	}
	defer a.Close()

	list, err := a.List()
	if err != nil {
		logMessage(LOG_ERROR, "[ERROR]", err)
		return matchs
	}
	for _, f := range list {
		err := a.EntryFor(f)
		if err != nil {
			return matchs
		}

		data, err := a.ReadAll()
		if err != nil {
			logMessage(LOG_ERROR, "[ERROR]", err)
			return matchs
		}

		buffer = append(buffer, data)
	}

	matchs, err = YaraScan(bytes.Join(buffer, []byte{}), rules)
	if err != nil {
		return matchs
	}

	return matchs
}

// LoadYaraRules compile yara rules from specified paths and return a pointer to the yara compiler
func LoadYaraRules(path []string) (compiler *yara.Compiler, err error) {
	compiler, err = yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize YARA compiler: %s", err.Error())
	}

	for _, dir := range path {
		f, err := os.ReadFile(dir)
		if err != nil {
			logMessage(LOG_ERROR, "[ERROR]", "Could not read rule file ", dir, err)
		}

		namespace := filepath.Base(dir)[:len(filepath.Base(dir))-4]
		if err = compiler.AddString(string(f), namespace); err != nil {
			logMessage(LOG_ERROR, "[ERROR]", "Could not load rule file ", dir, err)
		}
	}

	return compiler, nil
}

// CompileRules try to compile every rules from the given compiler
func CompileRules(compiler *yara.Compiler) (rules *yara.Rules, err error) {
	rules, err = compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("failed to compile rules: %s", err.Error())
	}

	return rules, err
}

// YaraScan use libyara to scan the specified content with a compiled rule
func YaraScan(content []byte, rules *yara.Rules) (match yara.MatchRules, err error) {
	sc, _ := yara.NewScanner(rules)
	var m yara.MatchRules
	err = sc.SetCallback(&m).ScanMem(content)
	return m, err
}

func FileAnalyzeYaraMatch(path string, rules *yara.Rules) bool {
	var err error
	var content []byte
	var result yara.MatchRules

	if _, err = os.Stat(path); err != nil {
		logMessage(LOG_ERROR, "[ERROR]", path, err)
	} else {
		// read file content
		content, err = os.ReadFile(path)
		if err != nil {
			logMessage(LOG_ERROR, "[ERROR]", path, err)
		}

		filetype, err := filetype.Match(content)
		if err != nil {
			logMessage(LOG_ERROR, "[ERROR]", path, err)
		}

		// cleaning memory if file size is greater than 512Mb
		if len(content) > 1024*1024*512 {
			defer debug.FreeOSMemory()
		}

		// archive or other file format scan
		if contains([]string{"application/x-tar", "application/x-7z-compressed", "application/zip", "application/vnd.rar"}, filetype.MIME.Value) {
			result = PerformArchiveYaraScan(path, rules)
		} else {
			result = PerformYaraScan(&content, rules)
		}
	}

	return len(result) > 0
}
