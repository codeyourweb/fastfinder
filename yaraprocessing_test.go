package main

import (
	"bytes"
	"log"
	"testing"
)

func TestYaraSearchEnumeration(t *testing.T) {
	r1 := EnumerateYaraInFolders([]string{"./tests/"})

	if len(r1) == 0 {
		t.Fatal("EnumerateYaraInFolders fails to retrieve test yara rules")
	}
}

func TestYaraRuleLoad(t *testing.T) {
	r1 := CompileYaraRules([]string{"tests/rule_test_standard.yar"}, "")

	if len(r1.GetRules()) != 1 {
		t.Fatal("CompileYaraRules was unable to compile a YARA rule")
	}

	r2 := CompileYaraRules([]string{"tests/rule_test_ciphered.yar"}, "testing")

	if len(r2.GetRules()) != 1 {
		t.Fatal("CompileYaraRules was unable to compile a RC4 ciphered YARA rule")
	}
}

func TestPerformYaraScan(t *testing.T) {
	r := CompileYaraRules([]string{"tests/rule_test_standard.yar"}, "")
	d := []byte("TestFindInFilesContent")
	r1, err := PerformYaraScan(&d, r)

	if err != nil || len(r1) != 1 {
		t.Fatal("")
	}
}

func TestYaraMatchAndResultOutput(t *testing.T) {
	r := CompileYaraRules([]string{"tests/rule_test_standard.yar"}, "")
	var buffer bytes.Buffer
	LogTesting(true)
	log.SetOutput(&buffer)

	r1 := FileAnalyzeYaraMatch("finder_test.go", r, 512, 512)
	LogTesting(false)

	if !r1 {
		log.Fatal("FileAnalyzeYaraMatch fails to match on testing file")
	}

	if !bytes.Contains(buffer.Bytes(), []byte("ALERT")) {
		t.Fatal("FileAnalyzeYaraMatch does not output YARA match")
	}

}
