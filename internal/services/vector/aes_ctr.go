package vector

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

type AESCTRParams struct {
	KeyHex   string `json:"key_hex,omitempty"`   // 16, 24, 32 bytes (hex)
	IVHex    string `json:"iv_hex,omitempty"`    // 16 bytes (hex)
	InputHex string `json:"input_hex,omitempty"` // plaintext hex; generated if empty
	Size     int    `json:"size,omitempty"`      // bytes for random plaintext
}

func GenerateAESCTR(p AESCTRParams) (inputHex, outputHex string, paramsOut AESCTRParams, err error) {
	var key []byte
	if p.KeyHex != "" {
		key, err = hex.DecodeString(p.KeyHex); if err != nil { return "", "", p, err }
		if !(len(key) == 16 || len(key) == 24 || len(key) == 32) {
			return "", "", p, errors.New("key must be 16/24/32 bytes")
		}
	} else {
		key = make([]byte, 32)
		if _, err = io.ReadFull(rand.Reader, key); err != nil { return "", "", p, err }
	}
	var iv []byte
	if p.IVHex != "" {
		iv, err = hex.DecodeString(p.IVHex); if err != nil { return "", "", p, err }
		if len(iv) != aes.BlockSize { return "", "", p, errors.New("iv must be 16 bytes") }
	} else {
		iv = make([]byte, aes.BlockSize)
		if _, err = io.ReadFull(rand.Reader, iv); err != nil { return "", "", p, err }
	}
	var pt []byte
	if p.InputHex != "" {
		pt, err = hex.DecodeString(p.InputHex); if err != nil { return "", "", p, err }
	} else {
		if p.Size <= 0 { p.Size = 32 }
		pt = make([]byte, p.Size)
		if _, err = io.ReadFull(rand.Reader, pt); err != nil { return "", "", p, err }
	}

	block, err := aes.NewCipher(key); if err != nil { return "", "", p, err }
	stream := cipher.NewCTR(block, iv)
	ct := make([]byte, len(pt))
	stream.XORKeyStream(ct, pt)

	outParams := AESCTRParams{
		KeyHex: hex.EncodeToString(key),
		IVHex: hex.EncodeToString(iv),
		InputHex: hex.EncodeToString(pt),
	}
	return outParams.InputHex, hex.EncodeToString(ct), outParams, nil
}
