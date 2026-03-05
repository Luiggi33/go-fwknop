package spa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

func pkcs7Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func pkcs7Strip(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
}

func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	paddedPlaintext := pkcs7Padding(plaintext, blockSize)

	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(paddedPlaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, paddedPlaintext)
	return append(iv, ciphertext...), nil
}

func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < 32 {
		return nil, errors.New("provided data doesn't match expectations")
	}

	iv, ciphertext := data[:16], data[16:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()

	if len(ciphertext)%blockSize != 0 {
		return nil, errors.New("provided data doesn't match expectations")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	unpaddedCiphertext, err := pkcs7Strip(ciphertext, blockSize)
	if err != nil {
		return nil, errors.New("provided data doesn't match expectations")
	}
	return unpaddedCiphertext, nil
}

func ComputeHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func VerifyHMAC(key, data, provided []byte) bool {
	return hmac.Equal(ComputeHMAC(key, data), provided)
}

func PayloadDigest(ivAndCiphertext []byte) string {
	h := sha256.Sum256(ivAndCiphertext)
	return hex.EncodeToString(h[:])
}
