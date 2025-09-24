package vector

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
)

type AESCBCTestMode string

const (
	KAT AESCBCTestMode = "KAT"
	MMT AESCBCTestMode = "MMT"
	MCT AESCBCTestMode = "MCT"
)

type AESCBGParams struct {
	KeyBits         int
	Count           int
	IncludeExpected bool
}

type EncRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext,omitempty"`
}
type DecRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext,omitempty"`
}

type AESCBCTestVector struct {
	Algorithm string      `json:"algorithm"`
	Mode      string      `json:"mode"`
	TestMode  string      `json:"test_mode"`
	KeyBits   int         `json:"key_bits"`
	Encrypt   []EncRecord `json:"encrypt"`
	Decrypt   []DecRecord `json:"decrypt"`
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return b
}

// GenerateAESCBCTestVectors produces 10 vectors (default) similar to NIST .rsp style.
func GenerateAESCBCTestVectors(test AESCBCTestMode, p AESCBGParams) (AESCBCTestVector, error) {
	if p.Count <= 0 {
		p.Count = 10
	}
	if p.KeyBits != 128 && p.KeyBits != 192 && p.KeyBits != 256 {
		return AESCBCTestVector{}, errors.New("key_bits must be 128/192/256")
	}
	keyLen := p.KeyBits / 8
	var out AESCBCTestVector
	out.Algorithm = "AES"
	out.Mode = "CBC"
	out.TestMode = string(test)
	out.KeyBits = p.KeyBits

	switch test {
	case KAT:
		// GFSbox-like: zero key/IV, random plaintext blocks
		key := make([]byte, keyLen) // all-zero
		iv := make([]byte, aes.BlockSize)
		blk, _ := aes.NewCipher(key)
		cbcEncr := cipher.NewCBCEncrypter(blk, iv)
		cbcDecr := cipher.NewCBCDecrypter(blk, iv)

		for i := 0; i < p.Count; i++ {
			pt := randBytes(aes.BlockSize)
			ct := make([]byte, aes.BlockSize)
			cbcEncr.CryptBlocks(ct, pt)

			enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
			dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
			if p.IncludeExpected {
				enc.Ciphertext = hex.EncodeToString(ct)
				// for decrypt, compute PT again (already have pt)
				dec.Plaintext = hex.EncodeToString(pt)
			}
			out.Encrypt = append(out.Encrypt, enc)
			out.Decrypt = append(out.Decrypt, dec)

			// reset IV state for CBC for each record per .rsp convention
			cbcEncr = cipher.NewCBCEncrypter(blk, iv)
			cbcDecr = cipher.NewCBCDecrypter(blk, iv)
			_ = cbcDecr // kept for symmetry
		}
	case MMT:
		// Multi-block message: 3 blocks random, zero key/IV
		key := make([]byte, keyLen)
		iv := make([]byte, aes.BlockSize)
		blk, _ := aes.NewCipher(key)
		for i := 0; i < p.Count; i++ {
			msg := randBytes(aes.BlockSize * 3)
			ct := make([]byte, len(msg))
			cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, msg)

			// Only emit the first block in PT/CT for compactness; full message goes in notes-like fields (omitted).
			enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:aes.BlockSize])}
			dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:aes.BlockSize])}
			if p.IncludeExpected {
				enc.Ciphertext = hex.EncodeToString(ct[:aes.BlockSize])
				dec.Plaintext = hex.EncodeToString(msg[:aes.BlockSize])
			}
			out.Encrypt = append(out.Encrypt, enc)
			out.Decrypt = append(out.Decrypt, dec)
		}
	case MCT:
		// Monte Carlo (simplified): 1000 iterations CBC over a single block seed per vector.
		key := make([]byte, keyLen)
		iv := make([]byte, aes.BlockSize)
		blk, _ := aes.NewCipher(key)
		for i := 0; i < p.Count; i++ {
			seedPT := randBytes(aes.BlockSize)
			pt := make([]byte, aes.BlockSize)
			copy(pt, seedPT)
			ivWork := make([]byte, aes.BlockSize)
			copy(ivWork, iv)
			for j := 0; j < 1000; j++ {
				cbc := cipher.NewCBCEncrypter(blk, ivWork)
				ct := make([]byte, aes.BlockSize)
				cbc.CryptBlocks(ct, pt)
				// next iteration uses previous ct as IV; pt becomes ct
				copy(ivWork, ct)
				copy(pt, ct)
			}
			// final pt == final ct of last round
			finalCT := make([]byte, aes.BlockSize)
			copy(finalCT, pt)

			enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(seedPT)}
			dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
			if p.IncludeExpected {
				// For ENCRYPT we publish the finalCT
				enc.Ciphertext = hex.EncodeToString(finalCT)
				// For DECRYPT we publish the seedPT, acknowledging this is a simplified MCT
				dec.Plaintext = hex.EncodeToString(seedPT)
			}
			out.Encrypt = append(out.Encrypt, enc)
			out.Decrypt = append(out.Decrypt, dec)
		}
	default:
		return AESCBCTestVector{}, errors.New("unsupported test mode")
	}
	return out, nil
}

// Optional formatter to .txt style similar to NIST .rsp
func (v AESCBCTestVector) ToTXT() string {
	var b strings.Builder
	b.WriteString("[ENCRYPT]\n\n")
	for _, r := range v.Encrypt {
		b.WriteString("COUNT = ")
		b.WriteString(fmtInt(r.Count))
		b.WriteString("\n")
		b.WriteString("KEY = ")
		b.WriteString(strings.ToLower(r.KeyHex))
		b.WriteString("\n")
		b.WriteString("IV = ")
		b.WriteString(strings.ToLower(r.IVHex))
		b.WriteString("\n")
		b.WriteString("PLAINTEXT = ")
		b.WriteString(strings.ToLower(r.Plaintext))
		b.WriteString("\n\n")
	}
	b.WriteString("[DECRYPT]\n\n")
	for _, r := range v.Decrypt {
		b.WriteString("COUNT = ")
		b.WriteString(fmtInt(r.Count))
		b.WriteString("\n")
		b.WriteString("KEY = ")
		b.WriteString(strings.ToLower(r.KeyHex))
		b.WriteString("\n")
		b.WriteString("IV = ")
		b.WriteString(strings.ToLower(r.IVHex))
		b.WriteString("\n")
		b.WriteString("CIPHERTEXT = ")
		b.WriteString(strings.ToLower(r.Ciphertext))
		b.WriteString("\n\n")
	}
	return b.String()
}

func fmtInt(i int) string {
	return strconv.Itoa(i)
}
