package p

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
)

type Password struct {
	Diggest    func() hash.Hash
	SaltSize   int
	KeyLen     int
	Iterations int
}

func NewPassword(diggest func() hash.Hash, saltSize int, keyLen int, iter int) *Password {
	return &Password{
		Diggest:    diggest,
		SaltSize:   saltSize,
		KeyLen:     keyLen,
		Iterations: iter,
	}
}

func (p *Password) HashPassword(password string) (string, error) {
	salt, err := generateSalt(p.SaltSize)
	if err != nil {
		return "", err
	}
	subkey := pbkdf2.Key([]byte(password), salt, p.Iterations, p.KeyLen, p.Diggest)
	var outputBytes = make([]byte, 1 + p.SaltSize + p.KeyLen)
	outputBytes[0] = 0x00 // format marker
	copy(outputBytes[1:], salt)
	copy(outputBytes[1+p.SaltSize:], subkey)
	cipherText := base64.StdEncoding.EncodeToString(outputBytes)
	return cipherText, nil
}

func (p *Password) VerifyPassword(password, cipherText string) (bool, error) {
	inputBytes, _ := base64.StdEncoding.DecodeString(cipherText)
	if len(inputBytes) != 1 + p.SaltSize + p.KeyLen || inputBytes[0] != 0x00 {
		return false, errors.New("wrong length or version header")
	}
	var salt = make([]byte, p.SaltSize)
	copy(salt, inputBytes[1:p.SaltSize+1])
	var expectedSubkey = make([]byte, p.KeyLen)
	copy(expectedSubkey, inputBytes[1+p.SaltSize:])
	actualSubkey := pbkdf2.Key([]byte(password), salt, p.Iterations, p.KeyLen, p.Diggest)
	return equal(expectedSubkey, actualSubkey), nil
}

func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func equal(expectedSubkey []byte, actualSubkey []byte) bool {
	diff := uint64(len(expectedSubkey)) ^ uint64(len(actualSubkey))
	for i := 0; i < len(expectedSubkey) && i < len(actualSubkey); i++ {
		diff |= uint64(expectedSubkey[i]) ^ uint64(actualSubkey[i])
	}
	return diff == 0
}