package main

import (
	"fmt"
	"go-aes-encryption-example/utils"
)

func main() {
	plaintext := "secret"
	key := "AES256Key-32Characters1234567890"

	enc := utils.NewAes()
	ciphertext, _ := enc.Encrypt(plaintext, key)
	fmt.Printf("Encrypt: %s -> %s\n", plaintext, ciphertext)

	decrypted, _ := enc.Decrypt(ciphertext, key)
	fmt.Printf("Decrypt: %s -> %s\n", ciphertext, decrypted)
}