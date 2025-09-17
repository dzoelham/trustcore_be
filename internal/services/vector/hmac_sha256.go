package vector

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

type HMACSHA256Params struct {
	KeyHex   string `json:"key_hex,omitempty"`   // optional; if empty generate 32 bytes
	InputHex string `json:"input_hex,omitempty"` // if empty generate
	Size     int    `json:"size,omitempty"`
}

func GenerateHMACSHA256(p HMACSHA256Params) (inputHex, outputHex string, paramsOut HMACSHA256Params, err error) {
	var key []byte
	if p.KeyHex != "" {
		key, err = hex.DecodeString(p.KeyHex); if err != nil { return "", "", p, err }
	} else {
		key = make([]byte, 32)
		if _, err = io.ReadFull(rand.Reader, key); err != nil { return "", "", p, err }
	}
	var in []byte
	if p.InputHex != "" {
		in, err = hex.DecodeString(p.InputHex); if err != nil { return "", "", p, err }
	} else {
		if p.Size <= 0 { p.Size = 32 }
		in = make([]byte, p.Size)
		if _, err = io.ReadFull(rand.Reader, in); err != nil { return "", "", p, err }
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(in)
	out := mac.Sum(nil)

	outParams := HMACSHA256Params{
		KeyHex:  hex.EncodeToString(key),
		InputHex: hex.EncodeToString(in),
	}
	return outParams.InputHex, hex.EncodeToString(out), outParams, nil
}
