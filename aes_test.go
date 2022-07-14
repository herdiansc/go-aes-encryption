package goaesencryption

import (
	"crypto/cipher"
	"errors"
	"io"
	"testing"
)

// MockBlock implements the cipher.Block interface
type MockBlock struct {
	MockBlockSize       func() int
	MockEncrypt         func(a, b []byte)
	MockDecrypt         func(a, b []byte)
	MockNewGCM          func(cipher cipher.Block) (cipher.AEAD, error)
	MockNewCBCEncrypter func([]byte) cipher.BlockMode
	MockNewCBCDecrypter func([]byte) cipher.BlockMode
	MockNewCTR          func([]byte) cipher.Stream
}

func (block *MockBlock) BlockSize() int      { return block.MockBlockSize() }
func (block *MockBlock) Encrypt(a, b []byte) { block.MockEncrypt(a, b) }
func (block *MockBlock) Decrypt(a, b []byte) { block.MockDecrypt(a, b) }
func (block *MockBlock) NewGCM(cipher cipher.Block) (cipher.AEAD, error) {
	return block.MockNewGCM(cipher)
}
func (block *MockBlock) NewCBCEncrypter(a []byte) cipher.BlockMode {
	return block.MockNewCBCEncrypter(a)
}
func (block *MockBlock) NewCBCDecrypter(a []byte) cipher.BlockMode {
	return block.MockNewCBCDecrypter(a)
}
func (block *MockBlock) NewCTR(a []byte) cipher.Stream { return block.MockNewCTR(a) }

// MockAEAD implements the cipher.AEAD interface
type MockAEAD struct {
	MockNonceSize    func() int
	MockOverhead     func() int
	MockSeal         func(a, b, c, d []byte) []byte
	MockOpen         func(a, b, c, d []byte) ([]byte, error)
	MockInAESPackage func() bool
}

func (aead *MockAEAD) NonceSize() int                         { return aead.MockNonceSize() }
func (aead *MockAEAD) Overhead() int                          { return aead.MockOverhead() }
func (aead *MockAEAD) Seal(a, b, c, d []byte) []byte          { return aead.MockSeal(a, b, c, d) }
func (aead *MockAEAD) Open(a, b, c, d []byte) ([]byte, error) { return aead.MockOpen(a, b, c, d) }
func (aead *MockAEAD) InAESPackage() bool                     { return aead.MockInAESPackage() }

var (
	SuccessNewCipher = func(key []byte) (cipher.Block, error) {
		return &MockBlock{}, nil
	}
	FailedNewCipher = func(key []byte) (cipher.Block, error) {
		return nil, errors.New("error")
	}
	SuccessNewGCM = func(cipher cipher.Block) (cipher.AEAD, error) {
		return &MockAEAD{
			MockNonceSize: func() int {
				return 0
			},
			MockOpen: func(a, b, c, d []byte) ([]byte, error) {
				return []byte(`SecretText`), nil
			},
			MockSeal: func(a, b, c, d []byte) []byte {
				return []byte(`Ciphertext123`)
			},
		}, nil
	}
	FailedNewGCM = func(cipher cipher.Block) (cipher.AEAD, error) {
		return &MockAEAD{}, errors.New("error")
	}
	SuccessDecodeString = func(s string) ([]byte, error) {
		return []byte{}, nil
	}
	FailedDecodeString = func(s string) ([]byte, error) {
		return nil, errors.New("error")
	}

	SuccessIoReadFull = func(r io.Reader, buf []byte) (n int, err error) {
		return 0, nil
	}
	FailedIoReadFull = func(r io.Reader, buf []byte) (n int, err error) {
		return 0, errors.New("error")
	}
	SuccessEncodeToString = func(source []byte) string {
		return "SecretText"
	}
	FailedEncodeToString = func(source []byte) string {
		return ""
	}
)

func TestAes_Decrypt(t *testing.T) {
	cases := []struct {
		testName     string
		key          string
		NewCipher    func(key []byte) (cipher.Block, error)
		NewGCM       func(cipher cipher.Block) (cipher.AEAD, error)
		DecodeString func(s string) ([]byte, error)
		plaintext    string
	}{
		{
			testName:     "1. Positive Test",
			key:          "ThisKeyHasToBe-32-CharactersLong",
			NewCipher:    SuccessNewCipher,
			NewGCM:       SuccessNewGCM,
			DecodeString: SuccessDecodeString,
			plaintext:    "SecretText",
		},
		{
			testName:     "2. Negative Test: Fail cipher initialization",
			key:          "ThisKeyHasToBe-32-CharactersLong",
			NewCipher:    FailedNewCipher,
			NewGCM:       SuccessNewGCM,
			DecodeString: SuccessDecodeString,
			plaintext:    "",
		},
		{
			testName:     "3. Negative Test: Fail GCM initialization",
			key:          "ThisKeyHasToBe-32-CharactersLong",
			NewCipher:    SuccessNewCipher,
			NewGCM:       FailedNewGCM,
			DecodeString: SuccessDecodeString,
			plaintext:    "",
		},
		{
			testName:     "4. Negative Test: Fail base64 decode",
			key:          "ThisKeyHasToBe-32-CharactersLong",
			NewCipher:    SuccessNewCipher,
			NewGCM:       SuccessNewGCM,
			DecodeString: FailedDecodeString,
			plaintext:    "",
		},
		{
			testName:     "5. Negative Test: empty key",
			key:          "",
			NewCipher:    SuccessNewCipher,
			NewGCM:       SuccessNewGCM,
			DecodeString: SuccessDecodeString,
			plaintext:    "",
		},
	}

	for _, c := range cases {
		t.Logf("Currently testing %s", c.testName)
		enc := NewAes()
		enc.NewCipher = c.NewCipher
		enc.NewGCM = c.NewGCM
		enc.DecodeString = c.DecodeString
		plaintext, _ := enc.Decrypt("CiphertextAbc123", c.key)
		if c.plaintext != plaintext {
			t.Errorf("Expected :%v, given: %v", c.plaintext, plaintext)
		}
	}
}

func TestAes_Encrypt(t *testing.T) {
	cases := []struct {
		testName       string
		key            string
		NewCipher      func(key []byte) (cipher.Block, error)
		NewGCM         func(cipher cipher.Block) (cipher.AEAD, error)
		EncodeToString func(source []byte) string
		IoReadFull     func(r io.Reader, buf []byte) (n int, err error)
		plaintext      string
	}{
		{
			testName:       "1. Positive Test",
			key:            "ThisKeyHasToBe-32-CharactersLong",
			NewCipher:      SuccessNewCipher,
			NewGCM:         SuccessNewGCM,
			EncodeToString: SuccessEncodeToString,
			IoReadFull:     SuccessIoReadFull,
			plaintext:      "SecretText",
		},
		{
			testName:       "2. Negative Test: Fail cipher initialization",
			key:            "ThisKeyHasToBe-32-CharactersLong",
			NewCipher:      FailedNewCipher,
			NewGCM:         SuccessNewGCM,
			EncodeToString: SuccessEncodeToString,
			IoReadFull:     SuccessIoReadFull,
			plaintext:      "",
		},
		{
			testName:       "3. Negative Test: Fail GCM initialization",
			key:            "ThisKeyHasToBe-32-CharactersLong",
			NewCipher:      SuccessNewCipher,
			NewGCM:         FailedNewGCM,
			EncodeToString: SuccessEncodeToString,
			IoReadFull:     SuccessIoReadFull,
			plaintext:      "",
		},
		{
			testName:       "4. Negative Test: Fail base64 decode",
			key:            "ThisKeyHasToBe-32-CharactersLong",
			NewCipher:      SuccessNewCipher,
			NewGCM:         SuccessNewGCM,
			EncodeToString: FailedEncodeToString,
			IoReadFull:     SuccessIoReadFull,
			plaintext:      "",
		},
		{
			testName:       "5. Negative Test: Fail io.ReadFull",
			key:            "ThisKeyHasToBe-32-CharactersLong",
			NewCipher:      SuccessNewCipher,
			NewGCM:         SuccessNewGCM,
			EncodeToString: SuccessEncodeToString,
			IoReadFull:     FailedIoReadFull,
			plaintext:      "",
		},
		{
			testName:       "6. Negative Test: Key is mandatory",
			key:            "",
			NewCipher:      SuccessNewCipher,
			NewGCM:         SuccessNewGCM,
			EncodeToString: SuccessEncodeToString,
			IoReadFull:     SuccessIoReadFull,
			plaintext:      "",
		},
	}

	for _, c := range cases {
		t.Logf("Currently testing %s", c.testName)
		enc := NewAes()
		enc.NewCipher = c.NewCipher
		enc.NewGCM = c.NewGCM
		enc.EncodeToString = c.EncodeToString
		enc.IoReadFull = c.IoReadFull
		plaintext, _ := enc.Encrypt("CiphertextAbc123", c.key)
		if c.plaintext != plaintext {
			t.Errorf("Expected :%v, given: %v", c.plaintext, plaintext)
		}
	}
}
