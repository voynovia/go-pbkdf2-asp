[![Build Status](https://travis-ci.org/wuriyanto48/go-pbkdf2.svg?branch=master)](https://travis-ci.org/wuriyanto48/go-pbkdf2)

# GO PBKDF2-ASP

PBKDF2 (Password-Based Key Derivation Function 2) https://en.wikipedia.org/wiki/PBKDF2

**This Implementation Based On**
Package pbkdf2 implements the key derivation function PBKDF2 as defined in RFC 2898 / PKCS #5 v2.0.
https://godoc.org/golang.org/x/crypto/pbkdf2

## USAGE

- **get first:**

```shell
go get github.com/voynovia/go-pbkdf2-asp
```

- **Hash a Password**
```go
package main

import(
	"fmt"
	"crypto/sha1"
	"github.com/voynovia/go-pbkdf2-asp"
    "log"
)

func main(){
    pass := NewPassword(sha1.New, 128/8, 256/8, 1000)
    cipherText, err := pass.HashPassword("lp-(1VWBkM$unx+")
    if err != nil {
      log.Fatal(err)
    }
	fmt.Println(cipherText)
}
```

- **Verify a Password**
```go
package main

import(
	"fmt"
	"crypto/sha1"
    "github.com/voynovia/go-pbkdf2-asp"
  "log"
)

func main(){
    pass := NewPassword(sha1.New, 128/8, 256/8, 1000)
    isValid, err := pass.VerifyPassword("igor.voynov", "ANj+MKAbgzHJGdmuFiY1AvZRX2pNUBZtvHBJhcgDSdwHKyVyj3CSl0RQDO0ndZlcLw==")
    if err != nil {
      log.Fatal(err)
    }
    fmt.Println(isValid)
}
```

## Doc

- **func NewPassword**
  ```go
  func NewPassword(func() hash.Hash, saltSize int, keyLen int, iterations int) *Password
  ```
  the drafted v2.1 specification allows use of all five FIPS Approved
  Hash Functions SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 for HMAC. To
  choose, you can pass the `New` functions from the different SHA packages to
  pbkdf2.Key.

- **func HashPassword**
  ```go
  func HashPassword("123456") (string, error)
  ```
  this function returning two fields: cipherText and error

- **func VerifyPassword**
  ```go
  func VerifyPassword("123456", "AOktxE08iNn/j6rpLBTw61FIQcNfQnYBwimZ/gtqHsWqhH2m0QMTa6FrqbC+OcWKEw==") (bool, error)
  ```
  this function returning two fields: 
  - true if your password is valid and false otherwise 
  - error if wrong length or version header
  
