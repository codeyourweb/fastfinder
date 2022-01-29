package main

import (
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/hillu/go-yara/v4"
)

func TestFindInFilesContent(t *testing.T) {
	p := []string{"TestFindInFilesContent"}
	r1 := checkForStringPattern("", []byte(p[0]), p)
	r2 := CheckFileChecksumAndContent("", []byte(p[0]), []string{}, p)
	if len(r1) != 1 || len(r2) != 1 {
		t.Fatal("checkForStringPattern or CheckFileChecksumAndContent doesn't match content in files")
	}
}

func TestFindFileChecksum(t *testing.T) {
	p := []string{"TestFindInFilesContent"}
	r1 := checkForChecksum("", []byte(p[0]), []string{"98073143a031423fd912da2c646d4aeb"})
	r2 := checkForChecksum("", []byte(p[0]), []string{"7c6c8c4e28098e526be3ad183343a9868515d84e"})
	r3 := checkForChecksum("", []byte(p[0]), []string{"3f0cc1212847f71146ee33e1e879588c328348aa0c0327c6ef4e0cfb13114cb8"})

	if len(r1) != 1 || len(r2) != 1 || len(r3) != 1 {
		t.Fatal("checkForChecksum fails find hash in content")
	}

	r4 := CheckFileChecksumAndContent("", []byte(p[0]), []string{"98073143a031423fd912da2c646d4aeb"}, []string{})
	r5 := CheckFileChecksumAndContent("", []byte(p[0]), []string{"7c6c8c4e28098e526be3ad183343a9868515d84e"}, []string{})
	r6 := CheckFileChecksumAndContent("", []byte(p[0]), []string{"3f0cc1212847f71146ee33e1e879588c328348aa0c0327c6ef4e0cfb13114cb8"}, []string{})

	if len(r4) != 1 || len(r5) != 1 || len(r6) != 1 {
		t.Fatal("CheckFileChecksumAndContent fails using checkForChecksum and matchs hash in content")
	}
}

func TestFindWithYARA(t *testing.T) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		t.Fatal("Fail to instanciate YARA compiler")
	}

	compiler.AddString("rule testing{\r\n\tstrings:\r\n\t\t$ = \"TestFindInFilesContent\"\r\n\tcondition:\r\n\t\tall of them\r\n}", "testing")
	r, err := compiler.GetRules()
	if err != nil {
		t.Fatal("Fail to compile YARA rules")
	}

	p := []byte("TestFindInFilesContent")
	r1, err := PerformYaraScan(&p, r)
	if err != nil || len(r1) != 1 {
		t.Fatal("PerformYaraScan fails to find string with YARA")
	}

	f := []string{"finder_test.go"}
	r2 := *FindInFilesContent(&f, []string{}, r, []string{}, false, 512, 512)
	if len(r2) != 1 {
		t.Fatal("FindInFilesContent fails to return YARA match")
	}
}

func TestPathMatching(t *testing.T) {
	var re []*regexp2.Regexp
	f := []string{"finder_test.go"}
	re = append(re, regexp2.MustCompile("finder_test\\.go", regexp2.IgnoreCase))
	r1 := PathsFinder(&f, re)

	if len(*r1) != 1 {
		t.Fatal("PathsFinder fails to match path with regex")
	}
}
