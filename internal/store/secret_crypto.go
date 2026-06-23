package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var ErrSecretKeyRequired = errors.New("secret encryption key required")

func encryptSecret(value, keyMaterial string) (ciphertext, nonce string, err error) {
	if keyMaterial == "" {
		return "", "", ErrSecretKeyRequired
	}
	key := sha256.Sum256([]byte(keyMaterial))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonceBytes := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", err
	}
	return base64.RawStdEncoding.EncodeToString(gcm.Seal(nil, nonceBytes, []byte(value), nil)), base64.RawStdEncoding.EncodeToString(nonceBytes), nil
}

func decryptSecret(ciphertext, nonce, keyMaterial string) (string, error) {
	if keyMaterial == "" {
		return "", ErrSecretKeyRequired
	}
	key := sha256.Sum256([]byte(keyMaterial))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertextBytes, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	nonceBytes, err := base64.RawStdEncoding.DecodeString(nonce)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonceBytes, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
