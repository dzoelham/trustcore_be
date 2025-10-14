package vector

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	goseed "github.com/RyuaNerin/go-krypto/seed"
)

type SEEDTestMode string

const (
	SEED_KAT SEEDTestMode = "KAT"
	SEED_MMT SEEDTestMode = "MMT"
	SEED_MCT SEEDTestMode = "MCT"
)

type SEEDGenParams struct {
	KeyBits         int
	Count           int
	IncludeExpected bool
	// Only used when test_mode == KAT. Allowed: GFSBOX | KEYSBOX | VARKEY | VARTXT
	KatVariant string
}

type SEEDEncRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // nonce/IV (empty for ECB)
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext,omitempty"`
}
type SEEDDecRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // nonce/IV (empty for ECB)
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext,omitempty"`
}

type SEEDTestVector struct {
	Algorithm string          `json:"algorithm"`
	Mode      string          `json:"mode"`
	TestMode  string          `json:"test_mode"`
	KeyBits   int             `json:"key_bits"`
	Encrypt   []SEEDEncRecord `json:"encrypt"`
	Decrypt   []SEEDDecRecord `json:"decrypt"`
}

func randBytesSEED(n int) []byte {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return b
}

func minSEED(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// encrypt one message according to mode.
// For ECB/CBC returns multiples of 16 bytes.
// For stream modes (CFB/OFB/CTR) the len equals len(pt).
// For GCM it returns ciphertext||tag.
func encryptOneSEED(mode string, blk cipher.Block, iv []byte, nonce []byte, pt []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("unsupported SEED mode %q", mode)
	}
}

func GenerateSEEDTestVectors(mode string, test string, p SEEDGenParams) (SEEDTestVector, error) {
	// Per RFC 4269, SEED uses a 128-bit key and 128-bit block.
	if p.KeyBits != 128 {
		return SEEDTestVector{}, errors.New("key_bits must be 128 for SEED")
	}
	mode = strings.ToUpper(strings.TrimSpace(mode))
	test = strings.ToUpper(strings.TrimSpace(test))

	var tmode SEEDTestMode
	switch test {
	case "KAT":
		tmode = SEED_KAT
	case "MMT":
		tmode = SEED_MMT
	case "MCT":
		tmode = SEED_MCT
	default:
		return SEEDTestVector{}, fmt.Errorf("unsupported test_mode %q", test)
	}

	switch mode {
	case "ECB", "CBC", "CFB", "OFB", "CTR", "GCM":
	default:
		return SEEDTestVector{}, fmt.Errorf("unsupported SEED mode %q", mode)
	}

	keyLen := p.KeyBits / 8 // 16
	var out SEEDTestVector
	out.Algorithm = "SEED"
	out.Mode = mode
	out.TestMode = string(tmode)
	out.KeyBits = p.KeyBits

	switch tmode {
	case SEED_KAT:
		variant := strings.ToUpper(strings.TrimSpace(p.KatVariant))
		if variant == "" {
			return SEEDTestVector{}, fmt.Errorf("KAT requires KatVariant (GFSBOX|KEYSBOX|VARKEY|VARTXT)")
		}

		zeroKey := make([]byte, keyLen)
		zeroIV := make([]byte, 16)
		zeroNonce := make([]byte, 12)

		switch variant {
		case "GFSBOX":
			// key=0, IV/nonce=0, plaintext random per COUNT
			blk, _ := goseed.NewCipher(zeroKey)
			for i := 0; i < p.Count; i++ {
				pt := randBytesSEED(16)
				ct, _ := encryptOneSEED(mode, blk, zeroIV, zeroNonce, pt)

				enc := SEEDEncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(zeroKey),
					IVHex:     ivOrNonceHex(mode, zeroIV, zeroNonce),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := SEEDDecRecord{
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
			// plaintext=0, IV/nonce=0, key random per COUNT
			pt := make([]byte, 16)
			for i := 0; i < p.Count; i++ {
				key := randBytesSEED(keyLen)
				blk, _ := goseed.NewCipher(key)
				ct, _ := encryptOneSEED(mode, blk, zeroIV, zeroNonce, pt)

				enc := SEEDEncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivOrNonceHex(mode, zeroIV, zeroNonce),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := SEEDDecRecord{
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
			// plaintext=0, IV/nonce=0
			pt := make([]byte, 16)
			limit := minSEED(p.Count, p.KeyBits) // one test per bit
			for i := 0; i < limit; i++ {
				key := setLeftmostBits(16, i+1) // COUNT=0 => 1 bit -> 0x80..
				blk, _ := goseed.NewCipher(key)
				ct, _ := encryptOneSEED(mode, blk, zeroIV, zeroNonce, pt)

				enc := SEEDEncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivOrNonceHex(mode, zeroIV, zeroNonce),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := SEEDDecRecord{
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
			// plaintext varies from 8000.. to ffff..
			// key=0, IV/nonce=0
			key := make([]byte, keyLen)
			blk, _ := goseed.NewCipher(key)
			limit := minSEED(p.Count, 128) // 128-bit block
			for i := 0; i < limit; i++ {
				pt := setLeftmostBits(16, i+1)
				ct, _ := encryptOneSEED(mode, blk, zeroIV, zeroNonce, pt)

				enc := SEEDEncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivOrNonceHex(mode, zeroIV, zeroNonce),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := SEEDDecRecord{
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
			return SEEDTestVector{}, fmt.Errorf("unsupported SEED KAT variant %q", variant)
		}

	case SEED_MMT:
		// MMT: plaintext grows with COUNT; cap to 10
		loopCount := p.Count
		if loopCount > 10 {
			loopCount = 10
		}
		for i := 0; i < loopCount; i++ {
			key := randBytesSEED(keyLen)
			iv := randBytesSEED(16)
			nonce := randBytesSEED(12)
			blk, _ := goseed.NewCipher(key)

			msg := randBytesSEED((i + 1) * 16)

			ct, _ := encryptOneSEED(mode, blk, iv, nonce, msg)

			enc := SEEDEncRecord{
				Count:     i,
				KeyHex:    hex.EncodeToString(key),
				IVHex:     ivOrNonceHex(mode, iv, nonce),
				Plaintext: hex.EncodeToString(msg),
			}
			dec := SEEDDecRecord{
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

	case SEED_MCT:
		// Monte Carlo Test: mirror AES MCT style used in this project
		const inner = 1000

		// Seeds when not provided externally
		key := randBytesSEED(keyLen)
		iv := randBytesSEED(16)
		pt0 := randBytesSEED(16)

		for i := 0; i < p.Count; i++ {
			keyRec := hex.EncodeToString(key)
			ivRec := hex.EncodeToString(iv)
			ptRec := hex.EncodeToString(pt0)

			blk, _ := goseed.NewCipher(key)
			lastCT := make([]byte, 16) // CT[j]
			prevCT := make([]byte, 16) // CT[j-1]

			pt := make([]byte, 16)
			copy(pt, pt0)

			switch mode {
			case "ECB":
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					blk.Encrypt(ct, pt)
					copy(pt, ct)         // PT[j+1] = CT[j]
					copy(prevCT, lastCT) // track CT[j-1]
					copy(lastCT, ct)     // CT[j]
				}

				enc := SEEDEncRecord{Count: i, KeyHex: keyRec, Plaintext: ptRec}
				dec := SEEDDecRecord{Count: i, KeyHex: keyRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				// For SEED (128-bit key only), XOR key with lastCT
				for k := 0; k < 16; k++ {
					key[k] ^= lastCT[k]
				}
				copy(pt0, lastCT) // next PT[0] = CT[j]

			case "CBC":
				iv_i := make([]byte, 16)
				copy(iv_i, iv)
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					if j == 0 {
						// CT[0] = E_K(PT[0] XOR IV[i]); PT[1] = IV[i]
						x := make([]byte, 16)
						for k := 0; k < 16; k++ {
							x[k] = pt[k] ^ iv_i[k]
						}
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

				enc := SEEDEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := SEEDDecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < 16; k++ {
					key[k] ^= lastCT[k]
				}
				copy(iv, lastCT)  // IV[i+1] = CT[j]
				copy(pt0, prevCT) // next PT[0] = CT[j-1]

			case "OFB":
				iv_i := make([]byte, 16)
				copy(iv_i, iv)
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					if j == 0 {
						stream := cipher.NewOFB(blk, iv_i)
						stream.XORKeyStream(ct, pt) // first step
						copy(pt, iv_i)              // PT[1] = IV[i]
					} else {
						blk.Encrypt(ct, pt) // CT[j] = E_K(PT[j])
						copy(pt, prevCT)    // PT[j+1] = CT[j-1]
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}

				enc := SEEDEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := SEEDDecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < 16; k++ {
					key[k] ^= lastCT[k]
				}
				copy(iv, lastCT)  // IV[i+1]
				copy(pt0, prevCT) // next PT[0]

			case "CFB":
				// Treat as CFB128
				iv_i := make([]byte, 16)
				copy(iv_i, iv)
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					if j == 0 {
						stream := cipher.NewCFBEncrypter(blk, iv_i)
						stream.XORKeyStream(ct, pt) // first block
						copy(pt, iv_i)              // PT[1] = IV[i]
					} else {
						blk.Encrypt(ct, pt) // CT[j] = E_K(PT[j])
						copy(pt, prevCT)    // PT[j+1] = CT[j-1]
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}

				enc := SEEDEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := SEEDDecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < 16; k++ {
					key[k] ^= lastCT[k]
				}
				copy(iv, lastCT)
				copy(pt0, prevCT)

			case "CTR":
				// Legacy/simple: not defined in AESAVS MCT
				ivWork := make([]byte, 16)
				copy(ivWork, iv)
				msg := make([]byte, 16)
				copy(msg, pt0)
				for j := 0; j < inner; j++ {
					stream := cipher.NewCTR(blk, ivWork)
					tmp := make([]byte, 16)
					stream.XORKeyStream(tmp, msg)
					copy(ivWork, tmp[:16])
					copy(msg, tmp)
				}
				last := make([]byte, 16)
				copy(last, msg)
				enc := SEEDEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := SEEDDecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(last)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(last)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
				for k := 0; k < 16; k++ {
					key[k] ^= last[k]
				}
				copy(iv, last)
				copy(pt0, last)

			case "GCM":
				// Legacy/simple path: not defined in AESAVS MCT
				aead, _ := cipher.NewGCM(blk)
				nonce := make([]byte, 12)
				msg := make([]byte, 16)
				copy(msg, pt0)
				var last []byte
				for j := 0; j < inner; j++ {
					last = aead.Seal(nil, nonce, msg, nil)
					copy(nonce, last[:minSEED(12, len(last))])
					copy(msg, last[:minSEED(16, len(last))])
				}
				enc := SEEDEncRecord{Count: i, KeyHex: keyRec, IVHex: hex.EncodeToString(nonce), Plaintext: ptRec}
				dec := SEEDDecRecord{Count: i, KeyHex: keyRec, IVHex: hex.EncodeToString(nonce), Ciphertext: hex.EncodeToString(last)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(last)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
				for k := 0; k < 16 && k < len(last); k++ {
					key[k] ^= last[k]
				}
				if len(last) >= 16 {
					copy(pt0, last[:16])
				}
			}
		}
	}

	return out, nil
}

// Optional formatter to .txt style similar to NIST .rsp
func (v SEEDTestVector) ToTXT() string {
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
