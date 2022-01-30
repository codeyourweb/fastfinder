package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"testing"
)

func TestRC4Cipher(t *testing.T) {
	input, err := hex.DecodeString("c31fc67a6d6fa9")
	if err != nil {
		t.Fatal("Fail to test RC4Cipher")
	}

	if !bytes.Contains(RC4Cipher([]byte(input), "testing"), []byte("testing")) {
		t.Fatal("RC4Cipher doesn't return appropriate result")
	}
}

func TestFileSHA256Sum(t *testing.T) {
	if FileSHA256Sum("tests/config_test_standard.yml") != "24def2a7f060ba758c682acef517b70e43ccd61002da5f7461103c2b9136694e" {
		t.Fatal("FileSHA256Sum returns unexpected result")
	}
}

func TestHostEnumeration(t *testing.T) {
	if len(GetHostname()) == 0 {
		t.Fatal("GetHostname does not return appropriate result")
	}

	if len(GetUsername()) == 0 {
		t.Fatal("GetUsername does not return appropriate result")
	}

	if len(GetCurrentDirectory()) == 0 {
		t.Fatal("GetCurrentDirectory does not return appropriate result")
	}
}

func TestValidUrl(t *testing.T) {
	if !IsValidUrl("http://www.github.com/codeyourweb/fastfinder") || IsValidUrl("http:\\www.github.com") {
		t.Fatal("IsValidUrl does not return appropriate result")
	}
}

func TestContains(t *testing.T) {
	if !Contains([]string{"a", "b"}, "a") || Contains([]string{"c,d"}, "a") {
		t.Fatal("Contains does not return appropriate result")
	}
}

func TestFileCopy(t *testing.T) {
	p := FileCopy("tests/config_test_standard.yml", "tests/", true)
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		t.Fatal("FileCopy fails copying specified file")
	}

	if FileSHA256Sum(p) != "0d77dfaf95d0adf67a27b8f44d4e1b7566efa77cf55344da85ce4a81ebe3b700" {
		t.Fatal("FileCopy base64 content return unexpected result")
	}

	os.Remove(p)
}
