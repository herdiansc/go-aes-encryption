package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

const AesKey string = "AES256Key-32Characters1234567890"

type Aes struct {
	NewCipher    func(key []byte) (cipher.Block, error)
	NewGCM       func(cipher cipher.Block) (cipher.AEAD, error)
	DecodeString func(s string) ([]byte, error)
}

func NewAes() Aes {
	return Aes{
		NewCipher:    aes.NewCipher,
		NewGCM:       cipher.NewGCM,
		DecodeString: base64.StdEncoding.DecodeString,
	}
}

//Decrypt used to decrypt ciphertext encrypted using AES.
func (enc Aes) Decrypt(encrypted string) (string, error) {
	block, err := enc.NewCipher([]byte(AesKey))
	if err != nil {
		return "", err
	}
	gcm, err := enc.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	data, err := enc.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	return string(plaintext), err
}