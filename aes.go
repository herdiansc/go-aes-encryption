package goaesencryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

type Aes struct {
	NewCipher      func(key []byte) (cipher.Block, error)
	NewGCM         func(cipher cipher.Block) (cipher.AEAD, error)
	DecodeString   func(s string) ([]byte, error)
	EncodeToString func(src []byte) string
	IoReadFull     func(r io.Reader, buf []byte) (n int, err error)
}

func NewAes() Aes {
	return Aes{
		NewCipher:      aes.NewCipher,
		NewGCM:         cipher.NewGCM,
		DecodeString:   base64.StdEncoding.DecodeString,
		EncodeToString: base64.StdEncoding.EncodeToString,
		IoReadFull:     io.ReadFull,
	}
}

//Decrypt used to decrypt ciphertext encrypted using AES.
func (enc Aes) Decrypt(encrypted, key string) (string, error) {
	block, err := enc.NewCipher([]byte(key))
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

//Encrypt used to encrypt plaintext using AES.
func (enc Aes) Encrypt(plaintext, key string) (string, error) {
	block, err := enc.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	gcm, err := enc.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := enc.IoReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	data := []byte(plaintext)
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	encrypted := enc.EncodeToString(ciphertext)
	return encrypted, nil
}