# go-aes-encryption
[![Build Status](https://travis-ci.org/herdiansc/go-aes-encryption-example.svg?branch=master)](https://travis-ci.org/herdiansc/go-aes-encryption-example)
[![Coverage Status](https://coveralls.io/repos/github/herdiansc/go-aes-encryption-example/badge.svg?branch=master)](https://coveralls.io/github/herdiansc/go-aes-encryption-example?branch=master)

This is a wrapper library for golang aes encryption.

## Example Use
```
package main

import (
	"fmt"
	aes "github.com/herdiansc/go-aes-encryption"
)

func main() {
	key := "ThisKeyHasToBe-32-CharactersLong"
	enc := aes.NewAes()
	c, _ := enc.Encrypt("A Secret!!!", key)
	fmt.Printf("ciphertext: %v\n", c)
	p, _ := enc.Decrypt(c, key)
	fmt.Printf("plaintext: %v\n", p)
}

```