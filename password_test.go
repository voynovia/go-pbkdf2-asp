package p

import (
	"crypto/sha1"
	"testing"
)

func TestPbkdf2ReturnFalse(t *testing.T) {
	pass := NewPassword(sha1.New, 128/8, 256/8, 1000)
	cipherText, _ := pass.HashPassword("12345")
	isValid, _ := pass.VerifyPassword("1234", cipherText)
	if isValid {
		t.Error("Verify Password was expected to return false : but result is ", isValid)
	}
}

func TestPbkdf2ReturnTrue(t *testing.T) {
	pass := NewPassword(sha1.New, 128/8, 256/8, 1000)
	cipherText, _ := pass.HashPassword("12345")
	isValid, _ := pass.VerifyPassword("12345", cipherText)
	if !isValid {
		t.Error("Verify Password was expected to return true : but result is ", isValid)
	}
}
