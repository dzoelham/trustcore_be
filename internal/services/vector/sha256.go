package vector

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

type SHA256Params struct {
	InputHex string `json:"input_hex,omitempty"` // if empty, generate random input
	Size     int    `json:"size,omitempty"`      // bytes for random input
}

func GenerateSHA256(p SHA256Params) (inputHex, outputHex string, err error) {
	var in []byte
	if p.InputHex != "" {
		in, err = hex.DecodeString(p.InputHex)
		if err != nil { return "", "", err }
	} else {
		if p.Size <= 0 { p.Size = 32 }
		in = make([]byte, p.Size)
		if _, err = io.ReadFull(rand.Reader, in); err != nil { return "", "", err }
	}
	sum := sha256.Sum256(in)
	return hex.EncodeToString(in), hex.EncodeToString(sum[:]), nil
}
