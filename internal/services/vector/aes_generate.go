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
		if len(pt)%16 != 0 {
			return nil, fmt.Errorf("ECB requires full blocks: got %%d")

		}
		ct := make([]byte, len(pt))
		for off := 0; off < len(pt); off += 16 {
			blk.Encrypt(ct[off:off+16], pt[off:off+16])
		}
		return ct, nil
	case "CBC":
		if len(pt)%16 != 0 {
			return nil, fmt.Errorf("ECB requires full blocks: got %%d")
		}
		ct := make([]byte, len(pt))
		cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, pt)
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

		// MMT: plaintext grows with COUNT; cap to 10 per AESAVS convention.
		loopCount := p.Count
		if loopCount > 10 {
			loopCount = 10
		}
		for i := 0; i < loopCount; i++ {
			// Fresh random key and IV/nonce for each COUNT
			key := randBytes(keyLen)
			iv := randBytes(16)
			nonce := randBytes(12)
			blk, _ := aes.NewCipher(key)

			// Plaintext length grows with COUNT: (i+1) * 16 bytes
			msg := randBytes((i + 1) * 16)

			// Encrypt entire message according to mode
			ct, _ := encryptOne(mode, blk, iv, nonce, msg)

			enc := EncRecord{
				Count:     i,
				KeyHex:    hex.EncodeToString(key),
				IVHex:     ivOrNonceHex(mode, iv, nonce),
				Plaintext: hex.EncodeToString(msg),
			}
			dec := DecRecord{
				Count:      i,
				KeyHex:     enc.KeyHex,
				IVHex:      enc.IVHex,
				Ciphertext: hex.EncodeToString(ct),
			}
			if p.IncludeExpected {
				enc.Ciphertext = hex.EncodeToString(ct)
				dec.Plaintext = hex.EncodeToString(msg)
			}
			out.Encrypt = append(out.Encrypt, enc)
			out.Decrypt = append(out.Decrypt, dec)
		}

	case MCT:
		// AESAVS Monte Carlo Test (MCT) per NIST AESAVS §6.4.
		// ECB, CBC, OFB, CFB (treated as CFB128) implemented as specified.
		// CTR and GCM remain legacy/simple to preserve compatibility.
		const inner = 1000

		// Seeds when not provided externally
		key := randBytes(keyLen) // 16, 24, or 32
		iv := randBytes(16)
		pt0 := randBytes(16)

		for i := 0; i < p.Count; i++ {
			keyRec := hex.EncodeToString(key)
			ivRec := hex.EncodeToString(iv)
			ptRec := hex.EncodeToString(pt0)

			blk, _ := aes.NewCipher(key)
			lastCT := make([]byte, 16) // CT[j]
			prevCT := make([]byte, 16) // CT[j-1]

			pt := make([]byte, 16)
			copy(pt, pt0)

			switch mode {
			case "ECB":
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					blk.Encrypt(ct, pt)
					copy(pt, ct)          // PT[j+1] = CT[j]
					copy(prevCT, lastCT)  // track CT[j-1]
					copy(lastCT, ct)      // CT[j]
				}

				enc := EncRecord{Count: i, KeyHex: keyRec, Plaintext: ptRec}
				dec := DecRecord{Count: i, KeyHex: keyRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				switch p.KeyBits {
				case 128:
					for k := 0; k < 16; k++ { key[k] ^= lastCT[k] }
				case 192:
					tmp := make([]byte, 24)
					copy(tmp[:8], prevCT[8:16])
					copy(tmp[8:], lastCT[:])
					for k := 0; k < 24; k++ { key[k] ^= tmp[k] }
				case 256:
					tmp := make([]byte, 32)
					copy(tmp[:16], prevCT[:])
					copy(tmp[16:], lastCT[:])
					for k := 0; k < 32; k++ { key[k] ^= tmp[k] }
				}
				copy(pt0, lastCT) // next PT[0] = CT[j]

			case "CBC":
				iv_i := make([]byte, 16); copy(iv_i, iv)
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					if j == 0 {
						// CT[0] = E_K(PT[0] XOR IV[i]); PT[1] = IV[i]
						x := make([]byte, 16)
						for k := 0; k < 16; k++ { x[k] = pt[k] ^ iv_i[k] }
						blk.Encrypt(ct, x)
						copy(pt, iv_i)
					} else {
						// CT[j] = E_K(PT[j]); PT[j+1] = CT[j-1]
						blk.Encrypt(ct, pt)
						copy(pt, prevCT)
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}

				enc := EncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := DecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				switch p.KeyBits {
				case 128:
					for k := 0; k < 16; k++ { key[k] ^= lastCT[k] }
				case 192:
					tmp := make([]byte, 24)
					copy(tmp[:8], prevCT[8:16])
					copy(tmp[8:], lastCT[:])
					for k := 0; k < 24; k++ { key[k] ^= tmp[k] }
				case 256:
					tmp := make([]byte, 32)
					copy(tmp[:16], prevCT[:])
					copy(tmp[16:], lastCT[:])
					for k := 0; k < 32; k++ { key[k] ^= tmp[k] }
				}
				copy(iv, lastCT)  // IV[i+1] = CT[j]
				copy(pt0, prevCT) // next PT[0] = CT[j-1]

			case "OFB":
				iv_i := make([]byte, 16); copy(iv_i, iv)
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					if j == 0 {
						stream := cipher.NewOFB(blk, iv_i)
						stream.XORKeyStream(ct, pt) // first step
						copy(pt, iv_i)              // PT[1] = IV[i]
					} else {
						blk.Encrypt(ct, pt)         // CT[j] = E_K(PT[j])
						copy(pt, prevCT)            // PT[j+1] = CT[j-1]
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}

				enc := EncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := DecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				switch p.KeyBits {
				case 128:
					for k := 0; k < 16; k++ { key[k] ^= lastCT[k] }
				case 192:
					tmp := make([]byte, 24)
					copy(tmp[:8], prevCT[8:16])
					copy(tmp[8:], lastCT[:])
					for k := 0; k < 24; k++ { key[k] ^= tmp[k] }
				case 256:
					tmp := make([]byte, 32)
					copy(tmp[:16], prevCT[:])
					copy(tmp[16:], lastCT[:])
					for k := 0; k < 32; k++ { key[k] ^= tmp[k] }
				}
				copy(iv, lastCT)  // IV[i+1]
				copy(pt0, prevCT) // next PT[0]

			case "CFB":
				// Treat as CFB128
				iv_i := make([]byte, 16); copy(iv_i, iv)
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					if j == 0 {
						stream := cipher.NewCFBEncrypter(blk, iv_i)
						stream.XORKeyStream(ct, pt) // first block
						copy(pt, iv_i)              // PT[1] = IV[i]
					} else {
						blk.Encrypt(ct, pt)         // CT[j] = E_K(PT[j])
						copy(pt, prevCT)            // PT[j+1] = CT[j-1]
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}

				enc := EncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := DecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				switch p.KeyBits {
				case 128:
					for k := 0; k < 16; k++ { key[k] ^= lastCT[k] }
				case 192:
					tmp := make([]byte, 24)
					copy(tmp[:8], prevCT[8:16])
					copy(tmp[8:], lastCT[:])
					for k := 0; k < 24; k++ { key[k] ^= tmp[k] }
				case 256:
					tmp := make([]byte, 32)
					copy(tmp[:16], prevCT[:])
					copy(tmp[16:], lastCT[:])
					for k := 0; k < 32; k++ { key[k] ^= tmp[k] }
				}
				copy(iv, lastCT)
				copy(pt0, prevCT)

			case "CTR":
				// Keep legacy/simple path: not defined in AESAVS MCT
				ivWork := make([]byte, 16); copy(ivWork, iv)
				msg := make([]byte, 16); copy(msg, pt0)
				for j := 0; j < inner; j++ {
					stream := cipher.NewCTR(blk, ivWork)
					tmp := make([]byte, 16)
					stream.XORKeyStream(tmp, msg)
					copy(ivWork, tmp[:16])
					copy(msg, tmp)
				}
				last := make([]byte, 16); copy(last, msg)
				enc := EncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := DecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(last)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(last)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
				for k := 0; k < min(len(key), 16); k++ { key[k] ^= last[k] }
				copy(iv, last)
				copy(pt0, last)

			case "GCM":
				// Keep legacy/simple path: not defined in AESAVS MCT
				aead, _ := cipher.NewGCM(blk)
				nonce := make([]byte, 12)
				msg := make([]byte, 16); copy(msg, pt0)
				var last []byte
				for j := 0; j < inner; j++ {
					last = aead.Seal(nil, nonce, msg, nil)
					copy(nonce, last[:min(12, len(last))])
					copy(msg, last[:min(16, len(last))])
				}
				enc := EncRecord{Count: i, KeyHex: keyRec, IVHex: hex.EncodeToString(nonce), Plaintext: ptRec}
				dec := DecRecord{Count: i, KeyHex: keyRec, IVHex: hex.EncodeToString(nonce), Ciphertext: hex.EncodeToString(last)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(last)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
				for k := 0; k < min(len(key), 16) && k < len(last); k++ { key[k] ^= last[k] }
				if len(last) >= 16 { copy(pt0, last[:16]) }
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
