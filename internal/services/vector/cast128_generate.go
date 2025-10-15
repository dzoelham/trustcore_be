package vector

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/cast5"
)

type CAST128TestMode string

const (
	CAST128_KAT CAST128TestMode = "KAT"
	CAST128_MMT CAST128TestMode = "MMT"
	CAST128_MCT CAST128TestMode = "MCT"
)

type CAST128GenParams struct {
	KeyBits         int
	Count           int
	IncludeExpected bool
	// Only used when test_mode == KAT. Allowed: GFSBOX | KEYSBOX | VARKEY | VARTXT
	KatVariant string
}

type CAST128EncRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // empty for ECB
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext,omitempty"`
}
type CAST128DecRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // empty for ECB
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext,omitempty"`
}

type CAST128TestVector struct {
	Algorithm string             `json:"algorithm"`
	Mode      string             `json:"mode"`
	TestMode  string             `json:"test_mode"`
	KeyBits   int                `json:"key_bits"`
	Encrypt   []CAST128EncRecord `json:"encrypt"`
	Decrypt   []CAST128DecRecord `json:"decrypt"`
}

// --- helpers ---

func randBytesCAST(n int) []byte {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return b
}

func minCAST(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fmtIntCAST(i int) string { return strconv.Itoa(i) }

func ivHexCAST(mode string, iv []byte) string {
	if strings.EqualFold(mode, "ECB") {
		return ""
	}
	return hex.EncodeToString(iv)
}

// setLeftmostBits returns a byte slice of length nBytes whose leftmost "bits" are set to 1.
func setLeftmostBitsCAST(nBytes, bits int) []byte {
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
		b[full] = ^byte(0xFF >> rem)
	}
	return b
}

// encrypt one message according to mode for 64-bit (8-byte) blocks.
// For ECB/CBC returns multiples of 8 bytes.
// For stream modes (CFB/OFB) the len equals len(pt).
func encryptOneCAST(mode string, blk cipher.Block, iv []byte, pt []byte) ([]byte, error) {
	switch strings.ToUpper(mode) {
	case "ECB":
		if len(pt)%8 != 0 {
			return nil, fmt.Errorf("ECB requires full blocks: got %%d")
		}
		ct := make([]byte, len(pt))
		for off := 0; off < len(pt); off += 8 {
			blk.Encrypt(ct[off:off+8], pt[off:off+8])
		}
		return ct, nil
	case "CBC":
		if len(pt)%8 != 0 {
			return nil, fmt.Errorf("CBC requires full blocks: got %%d")
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
	default:
		return nil, fmt.Errorf("unsupported CAST-128 mode %q", mode)
	}
}

// --- generator ---

func GenerateCAST128TestVectors(mode string, test string, p CAST128GenParams) (CAST128TestVector, error) {
	// CAST-128 (CAST5): 64-bit block, key from 40..128 bits (in 8-bit increments). Enforce 40..128 and divisible by 8.
	if p.KeyBits < 40 || p.KeyBits > 128 || p.KeyBits%8 != 0 {
		return CAST128TestVector{}, errors.New("key_bits must be 40..128 and a multiple of 8 for CAST-128")
	}
	if p.KeyBits != 128 {
		return CAST128TestVector{}, errors.New("key_bits must 128 CAST-128")
	}
	mode = strings.ToUpper(strings.TrimSpace(mode))
	test = strings.ToUpper(strings.TrimSpace(test))

	var tmode CAST128TestMode
	switch test {
	case "KAT":
		tmode = CAST128_KAT
	case "MMT":
		tmode = CAST128_MMT
	case "MCT":
		tmode = CAST128_MCT
	default:
		return CAST128TestVector{}, fmt.Errorf("unsupported test_mode %q", test)
	}

	switch mode {
	case "ECB", "CBC", "CFB", "OFB":
	default:
		return CAST128TestVector{}, fmt.Errorf("unsupported CAST-128 mode %q", mode)
	}

	keyLen := p.KeyBits / 8 // 5..16 bytes
	blockSize := 8          // 64-bit block

	var out CAST128TestVector
	out.Algorithm = "CAST-128"
	out.Mode = mode
	out.TestMode = string(tmode)
	out.KeyBits = p.KeyBits

	switch tmode {
	case CAST128_KAT:
		variant := strings.ToUpper(strings.TrimSpace(p.KatVariant))
		if variant == "" {
			return CAST128TestVector{}, fmt.Errorf("KAT requires KatVariant (GFSBOX|KEYSBOX|VARKEY|VARTXT)")
		}
		zeroKey := make([]byte, keyLen)
		zeroIV := make([]byte, blockSize)

		switch variant {
		case "GFSBOX":
			blk, _ := cast5.NewCipher(zeroKey)
			for i := 0; i < p.Count; i++ {
				pt := randBytesCAST(blockSize)
				ct, _ := encryptOneCAST(mode, blk, zeroIV, pt)

				enc := CAST128EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(zeroKey),
					IVHex:     ivHexCAST(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := CAST128DecRecord{
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
			pt := make([]byte, blockSize)
			for i := 0; i < p.Count; i++ {
				key := randBytesCAST(keyLen)
				blk, _ := cast5.NewCipher(key)
				ct, _ := encryptOneCAST(mode, blk, zeroIV, pt)

				enc := CAST128EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivHexCAST(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := CAST128DecRecord{
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
			// plaintext=0, varying key (leftmost bits set)
			pt := make([]byte, blockSize)
			limit := minCAST(p.Count, p.KeyBits) // up to 128
			for i := 0; i < limit; i++ {
				key := setLeftmostBitsCAST(keyLen, i+1)
				blk, _ := cast5.NewCipher(key)
				ct, _ := encryptOneCAST(mode, blk, zeroIV, pt)

				enc := CAST128EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivHexCAST(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := CAST128DecRecord{
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
			// key=0, varying plaintext (leftmost bits set)
			key := make([]byte, keyLen)
			blk, _ := cast5.NewCipher(key)
			limit := minCAST(p.Count, blockSize*8) // 64
			for i := 0; i < limit; i++ {
				pt := setLeftmostBitsCAST(blockSize, i+1)
				ct, _ := encryptOneCAST(mode, blk, zeroIV, pt)

				enc := CAST128EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivHexCAST(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := CAST128DecRecord{
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
			return CAST128TestVector{}, fmt.Errorf("unsupported CAST-128 KAT variant %q", variant)
		}

	case CAST128_MMT:
		loopCount := p.Count
		if loopCount > 10 {
			loopCount = 10
		}
		for i := 0; i < loopCount; i++ {
			key := randBytesCAST(keyLen)
			iv := randBytesCAST(blockSize)
			blk, _ := cast5.NewCipher(key)

			msg := randBytesCAST((i + 1) * blockSize)
			ct, _ := encryptOneCAST(mode, blk, iv, msg)

			enc := CAST128EncRecord{
				Count:     i,
				KeyHex:    hex.EncodeToString(key),
				IVHex:     ivHexCAST(mode, iv),
				Plaintext: hex.EncodeToString(msg),
			}
			dec := CAST128DecRecord{
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

	case CAST128_MCT:
		// Monte Carlo-like test similar to AES style, adapted for 64-bit blocks and variable key length (5..16 bytes).
		const inner = 1000

		key := randBytesCAST(keyLen)
		iv := randBytesCAST(blockSize)
		pt0 := randBytesCAST(blockSize)

		for i := 0; i < p.Count; i++ {
			keyRec := hex.EncodeToString(key)
			ivRec := hex.EncodeToString(iv)
			ptRec := hex.EncodeToString(pt0)

			blk, _ := cast5.NewCipher(key)
			lastCT := make([]byte, blockSize) // CT[j]
			prevCT := make([]byte, blockSize) // CT[j-1]

			pt := make([]byte, blockSize)
			copy(pt, pt0)

			switch mode {
			case "ECB":
				ct := make([]byte, blockSize)
				for j := 0; j < inner; j++ {
					blk.Encrypt(ct, pt)
					copy(pt, ct)         // PT[j+1] = CT[j]
					copy(prevCT, lastCT) // track CT[j-1]
					copy(lastCT, ct)     // CT[j]
				}

				enc := CAST128EncRecord{Count: i, KeyHex: keyRec, Plaintext: ptRec}
				dec := CAST128DecRecord{Count: i, KeyHex: keyRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < len(key); k++ {
					key[k] ^= lastCT[k%blockSize]
				}
				copy(pt0, lastCT)

			case "CBC":
				iv_i := make([]byte, blockSize)
				copy(iv_i, iv)
				ct := make([]byte, blockSize)
				for j := 0; j < inner; j++ {
					if j == 0 {
						x := make([]byte, blockSize)
						for k := 0; k < blockSize; k++ {
							x[k] = pt[k] ^ iv_i[k]
						}
						blk.Encrypt(ct, x)
						copy(pt, iv_i)
					} else {
						blk.Encrypt(ct, pt)
						copy(pt, prevCT)
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}

				enc := CAST128EncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := CAST128DecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < len(key); k++ {
					key[k] ^= lastCT[k%blockSize]
				}
				copy(iv, lastCT)  // next IV
				copy(pt0, prevCT) // next PT[0]

			case "OFB":
				iv_i := make([]byte, blockSize)
				copy(iv_i, iv)
				ct := make([]byte, blockSize)
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

				enc := CAST128EncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := CAST128DecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < len(key); k++ {
					key[k] ^= lastCT[k%blockSize]
				}
				copy(iv, lastCT)
				copy(pt0, prevCT)

			case "CFB":
				iv_i := make([]byte, blockSize)
				copy(iv_i, iv)
				ct := make([]byte, blockSize)
				for j := 0; j < inner; j++ {
					if j == 0 {
						stream := cipher.NewCFBEncrypter(blk, iv_i)
						stream.XORKeyStream(ct, pt) // first block
						copy(pt, iv_i)              // PT[1] = IV[i]
					} else {
						blk.Encrypt(ct, pt) // legacy/simple
						copy(pt, prevCT)    // PT[j+1] = CT[j-1]
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}

				enc := CAST128EncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := CAST128DecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < len(key); k++ {
					key[k] ^= lastCT[k%blockSize]
				}
				copy(iv, lastCT)
				copy(pt0, prevCT)
			}
		}
	}

	return out, nil
}

// Optional formatter similar to NIST .rsp style
func (v CAST128TestVector) ToTXT() string {
	var b strings.Builder
	b.WriteString("[ENCRYPT]\n\n")
	for _, r := range v.Encrypt {
		b.WriteString("COUNT = ")
		b.WriteString(fmtIntCAST(r.Count))
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
		b.WriteString(fmtIntCAST(r.Count))
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
