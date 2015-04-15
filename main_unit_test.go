package main

import (
	"testing"
)

func TestCookieValidation(t *testing.T) {

	signed := signCookie("hi, there", "mysecret")

	parsed, err := parseCookie(signed, "bob")

	if err == nil {
		t.Fatal("Expecting an error when decrypting with wrong key")
	}

	parsed, err = parseCookie(signed+"a", "mysecret")

	if err == nil {
		t.Fatal("Expecting an error when decrypting with wrong payload")
	}

	parsed, err = parseCookie(signed, "mysecret")

	if err != nil || parsed != "hi, there" {
		t.Fatal("Expecting a correctly validated cookie")
	}
}
