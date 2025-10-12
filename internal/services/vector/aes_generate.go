package vector

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type AESTestMode string

const (
	KAT AESTestMode = "KAT"
	MMT AESTestMode = "MMT"
	MCT AESTestMode = "MCT"
)

type AESGenParams struct {
	KeyBits         int
	Count           int
	IncludeExpected bool
	// Only used when test_mode == KAT for AES. Allowed: GFSBOX | KEYSBOX | VARKEY | VARTXT
	KatVariant string
}

type EncRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // nonce/IV (empty for ECB)
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext,omitempty"`
}
type DecRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // nonce/IV (empty for ECB)
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext,omitempty"`
}

type AESTestVector struct {
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// encrypt one block/message according to mode.
// For ECB/CBC the returned ciphertext is 16 bytes.
// For stream modes (CFB/OFB/CTR) the len equals len(pt).
// For GCM it returns ciphertext||tag.
func encryptOne(mode string, blk cipher.Block, iv []byte, nonce []byte, pt []byte) ([]byte, error) {
	switch strings.ToUpper(mode) {
	case "ECB":
		ct := make([]byte, 16)
		blk.Encrypt(ct, pt[:16])
		return ct, nil
	case "CBC":
		ct := make([]byte, 16)
		cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, pt[:16])
		return ct, nil
	case "CFB":
		ct := make([]byte, len(pt))
		cipher.NewCFBEncrypter(blk, iv).XORKeyStream(ct, pt)
		return ct, nil
	case "OFB":
		ct := make([]byte, len(pt))
		cipher.NewOFB(blk, iv).XORKeyStream(ct, pt)
		return ct, nil
	case "CTR":
		ct := make([]byte, len(pt))
		cipher.NewCTR(blk, iv).XORKeyStream(ct, pt)
		return ct, nil
	case "GCM":
		aead, err := cipher.NewGCM(blk)
		if err != nil {
			return nil, err
		}
		return aead.Seal(nil, nonce, pt, nil), nil
	default:
		return nil, fmt.Errorf("unsupported AES mode %q", mode)
	}
}

func GenerateAESTestVectors(mode string, test string, p AESGenParams) (AESTestVector, error) {
	switch p.KeyBits {
	case 128, 192, 256:
	default:
		return AESTestVector{}, errors.New("key_bits must be 128/192/256")
	}
	mode = strings.ToUpper(strings.TrimSpace(mode))
	test = strings.ToUpper(strings.TrimSpace(test))

	var tmode AESTestMode
	switch test {
	case "KAT":
		tmode = KAT
	case "MMT":
		tmode = MMT
	case "MCT":
		tmode = MCT
	default:
		return AESTestVector{}, fmt.Errorf("unsupported test_mode %q", test)
	}

	switch mode {
	case "ECB", "CBC", "CFB", "OFB", "CTR", "GCM":
	default:
		return AESTestVector{}, fmt.Errorf("unsupported AES mode %q", mode)
	}

	keyLen := p.KeyBits / 8
	var out AESTestVector
	out.Algorithm = "AES"
	out.Mode = mode
	out.TestMode = string(tmode)
	out.KeyBits = p.KeyBits

	switch tmode {
	case KAT:
		// Implement KAT sub-variants as requested.
		variant := strings.ToUpper(strings.TrimSpace(p.KatVariant))
		if variant == "" {
			// Be defensive: default to GFSBOX if caller didn't pass variant (handler should enforce this).
			variant = "GFSBOX"
		}

		zeroKey := make([]byte, keyLen)
		zeroIV := make([]byte, 16)
		zeroNonce := make([]byte, 12)

		switch variant {
		case "GFSBOX":
			// key=0, IV=0, plaintext random per COUNT
			blk, _ := aes.NewCipher(zeroKey)
			for i := 0; i < p.Count; i++ {
				pt := randBytes(16)
				ct, _ := encryptOne(mode, blk, zeroIV, zeroNonce, pt)

				enc := EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(zeroKey),
					IVHex:     ivOrNonceHex(mode, zeroIV, zeroNonce),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := DecRecord{
					Count:      i,
					KeyHex:     enc.KeyHex,
					IVHex:      enc.IVHex,
					Ciphertext: hex.EncodeToString(ct),
				}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}

		case "KEYSBOX":
			// plaintext=0, IV=0, key random per COUNT
			pt := make([]byte, 16)
			for i := 0; i < p.Count; i++ {
				key := randBytes(keyLen)
				blk, _ := aes.NewCipher(key)
				ct, _ := encryptOne(mode, blk, zeroIV, zeroNonce, pt)

				enc := EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivOrNonceHex(mode, zeroIV, zeroNonce),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := DecRecord{
					Count:      i,
					KeyHex:     enc.KeyHex,
					IVHex:      enc.IVHex,
					Ciphertext: hex.EncodeToString(ct),
				}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}

		case "VARKEY":
			// key varies from 8000.. to ffff.. (progressively setting leftmost bits)
			// plaintext=0, IV=0
			pt := make([]byte, 16)
			limit := min(p.Count, p.KeyBits) // one test per bit
			// limit := 128
			for i := range limit {
				key := setLeftmostBits(keyLen, i+1) // COUNT=0 => 1 bit -> 0x80..
				blk, _ := aes.NewCipher(key)
				ct, _ := encryptOne(mode, blk, zeroIV, zeroNonce, pt)

				enc := EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivOrNonceHex(mode, zeroIV, zeroNonce),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := DecRecord{
					Count:      i,
					KeyHex:     enc.KeyHex,
					IVHex:      enc.IVHex,
					Ciphertext: hex.EncodeToString(ct),
				}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}

		case "VARTXT":
			// plaintext varies from 8000.. to ffff.. (progressively setting leftmost bits)
			// key=0, IV=0
			key := make([]byte, keyLen)
			blk, _ := aes.NewCipher(key)
			limit := min(p.Count, 128) // one test per bit in a 128-bit block
			// limit := 128
			for i := range limit {
				pt := setLeftmostBits(16, i+1)
				ct, _ := encryptOne(mode, blk, zeroIV, zeroNonce, pt)

				enc := EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivOrNonceHex(mode, zeroIV, zeroNonce),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := DecRecord{
					Count:      i,
					KeyHex:     enc.KeyHex,
					IVHex:      enc.IVHex,
					Ciphertext: hex.EncodeToString(ct),
				}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}

		default:
			return AESTestVector{}, fmt.Errorf("unsupported AES KAT variant %q", variant)
		}

	case MMT:
		key := make([]byte, keyLen)
		iv := make([]byte, 16)
		nonce := make([]byte, 12)
		blk, _ := aes.NewCipher(key)
		for i := 0; i < p.Count; i++ {
			msg := randBytes(16 * 3)
			switch mode {
			case "ECB":
				ct := make([]byte, len(msg))
				for off := 0; off < len(msg); off += 16 {
					blk.Encrypt(ct[off:off+16], msg[off:off+16])
				}
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), Plaintext: hex.EncodeToString(msg[:16])}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, Ciphertext: hex.EncodeToString(ct[:16])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:16])
					dec.Plaintext = hex.EncodeToString(msg[:16])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CBC":
				ct := make([]byte, len(msg))
				cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, msg)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:16])}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:16])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:16])
					dec.Plaintext = hex.EncodeToString(msg[:16])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CFB":
				ct := make([]byte, len(msg))
				cipher.NewCFBEncrypter(blk, iv).XORKeyStream(ct, msg)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:16])}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:16])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:16])
					dec.Plaintext = hex.EncodeToString(msg[:16])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "OFB":
				ct := make([]byte, len(msg))
				cipher.NewOFB(blk, iv).XORKeyStream(ct, msg)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:16])}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:16])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:16])
					dec.Plaintext = hex.EncodeToString(msg[:16])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CTR":
				ct := make([]byte, len(msg))
				cipher.NewCTR(blk, iv).XORKeyStream(ct, msg)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:16])}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:16])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:16])
					dec.Plaintext = hex.EncodeToString(msg[:16])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "GCM":
				aead, _ := cipher.NewGCM(blk)
				ct := aead.Seal(nil, nonce, msg, nil)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(nonce), Plaintext: hex.EncodeToString(msg[:16])}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:16])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:16])
					dec.Plaintext = hex.EncodeToString(msg[:16])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}
		}

	case MCT:
		key := make([]byte, keyLen)
		iv := make([]byte, 16)
		blk, _ := aes.NewCipher(key)
		for i := 0; i < p.Count; i++ {
			pt := randBytes(16)
			switch mode {
			case "ECB":
				for j := 0; j < 1000; j++ {
					blk.Encrypt(pt, pt)
				}
				finalCT := make([]byte, 16)
				copy(finalCT, pt)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, Ciphertext: hex.EncodeToString(finalCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(finalCT)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CBC":
				ivWork := make([]byte, 16)
				copy(ivWork, iv)
				for j := 0; j < 1000; j++ {
					ct := make([]byte, 16)
					cipher.NewCBCEncrypter(blk, ivWork).CryptBlocks(ct, pt)
					copy(ivWork, ct)
					copy(pt, ct)
				}
				finalCT := make([]byte, 16)
				copy(finalCT, pt)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(finalCT)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CFB":
				ivWork := make([]byte, 16)
				copy(ivWork, iv)
				for j := 0; j < 1000; j++ {
					stream := cipher.NewCFBEncrypter(blk, ivWork)
					ct := make([]byte, 16)
					stream.XORKeyStream(ct, pt)
					copy(ivWork, ct)
					copy(pt, ct)
				}
				finalCT := make([]byte, 16)
				copy(finalCT, pt)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(finalCT)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "OFB":
				ivWork := make([]byte, 16)
				copy(ivWork, iv)
				for j := 0; j < 1000; j++ {
					stream := cipher.NewOFB(blk, ivWork)
					ct := make([]byte, 16)
					stream.XORKeyStream(ct, pt)
					copy(ivWork, ct)
					copy(pt, ct)
				}
				finalCT := make([]byte, 16)
				copy(finalCT, pt)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(finalCT)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CTR":
				ivWork := make([]byte, 16)
				copy(ivWork, iv)
				for j := 0; j < 1000; j++ {
					stream := cipher.NewCTR(blk, ivWork)
					ct := make([]byte, 16)
					stream.XORKeyStream(ct, pt)
					copy(ivWork, ct[:16])
					copy(pt, ct)
				}
				finalCT := make([]byte, 16)
				copy(finalCT, pt)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(finalCT)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "GCM":
				// A precise AES MCT for GCM is complex; keep the same simplified approach as original code.
				aead, _ := cipher.NewGCM(blk)
				nonceWork := make([]byte, 12)
				for j := 0; j < 1000; j++ {
					ct := aead.Seal(nil, nonceWork, pt, nil)
					copy(nonceWork, ct[:min(12, len(ct))])
					copy(pt, ct[:min(16, len(ct))])
				}
				finalCT := make([]byte, 16)
				copy(finalCT, pt)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(nonceWork), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(finalCT)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}
		}
	}
	return out, nil
}

// Optional formatter to .txt style similar to NIST .rsp
func (v AESTestVector) ToTXT() string {
	var b strings.Builder
	b.WriteString("[ENCRYPT]\n\n")
	for _, r := range v.Encrypt {
		b.WriteString("COUNT = ")
		b.WriteString(fmtInt(r.Count))
		b.WriteString("\n")
		b.WriteString("KEY = ")
		b.WriteString(strings.ToLower(r.KeyHex))
		b.WriteString("\n")
		if r.IVHex != "" {
			b.WriteString("IV = ")
			b.WriteString(strings.ToLower(r.IVHex))
			b.WriteString("\n")
		}
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
		if r.IVHex != "" {
			b.WriteString("IV = ")
			b.WriteString(strings.ToLower(r.IVHex))
			b.WriteString("\n")
		}
		b.WriteString("CIPHERTEXT = ")
		b.WriteString(strings.ToLower(r.Ciphertext))
		b.WriteString("\n\n")
	}
	return b.String()
}

func fmtInt(i int) string { return strconv.Itoa(i) }

func ivOrNonceHex(mode string, iv128 []byte, nonce96 []byte) string {
	if strings.ToUpper(mode) == "GCM" {
		return hex.EncodeToString(nonce96)
	}
	// ECB should be empty IV
	if strings.ToUpper(mode) == "ECB" {
		return ""
	}
	return hex.EncodeToString(iv128)
}

// setLeftmostBits returns a byte slice of length nBytes whose leftmost "bits" are set to 1.
// Example: nBytes=16, bits=1 -> 0x80 00 00 ...
//
//	nBytes=16, bits=2 -> 0xC0 00 00 ...
//	nBytes=16, bits=8 -> 0xFF 00 00 ...
//	nBytes=16, bits=9 -> 0xFF 0x80 00 ...
func setLeftmostBits(nBytes, bits int) []byte {
	if bits <= 0 {
		return make([]byte, nBytes)
	}
	if bits > nBytes*8 {
		bits = nBytes * 8
	}
	b := make([]byte, nBytes)
	full := bits / 8
	rem := bits % 8
	for i := 0; i < full; i++ {
		b[i] = 0xFF
	}
	if rem > 0 {
		// rem leftmost bits in next byte
		b[full] = ^byte(0xFF >> rem)
	}
	return b
}

// decryptOne is unused in generation but kept for parity/debugging.
func decryptOne(mode string, blk cipher.Block, iv []byte, nonce []byte, ct []byte) []byte {
	switch strings.ToUpper(mode) {
	case "ECB":
		pt := make([]byte, 16)
		blk.Decrypt(pt, ct[:16])
		return pt
	case "CBC":
		pt := make([]byte, 16)
		cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct[:16])
		return pt
	case "CFB":
		pt := make([]byte, len(ct))
		cipher.NewCFBDecrypter(blk, iv).XORKeyStream(pt, ct[:len(pt)])
		if len(pt) >= 16 {
			return pt[:16]
		}
		return pt
	case "OFB":
		pt := make([]byte, len(ct))
		cipher.NewOFB(blk, iv).XORKeyStream(pt, ct[:len(pt)])
		if len(pt) >= 16 {
			return pt[:16]
		}
		return pt
	case "CTR":
		pt := make([]byte, len(ct))
		cipher.NewCTR(blk, iv).XORKeyStream(pt, ct[:len(pt)])
		if len(pt) >= 16 {
			return pt[:16]
		}
		return pt
	case "GCM":
		aead, err := cipher.NewGCM(blk)
		if err != nil {
			return make([]byte, 16)
		}
		pt, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return make([]byte, 16)
		}
		if len(pt) >= 16 {
			return pt[:16]
		}
		return pt
	}
	return make([]byte, 16)
}
