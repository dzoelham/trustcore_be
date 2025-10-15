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

	gohight "github.com/RyuaNerin/go-krypto/hight"
)

type HIGHTTestMode string

const (
	HIGHT_KAT HIGHTTestMode = "KAT"
	HIGHT_MMT HIGHTTestMode = "MMT"
	HIGHT_MCT HIGHTTestMode = "MCT"
)

type HIGHTGenParams struct {
	KeyBits         int
	Count           int
	IncludeExpected bool
	// Only used when test_mode == KAT. Allowed: GFSBOX | KEYSBOX | VARKEY | VARTXT
	KatVariant string
}

type HIGHTEncRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // empty for ECB
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext,omitempty"`
}
type HIGHTDecRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // empty for ECB
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext,omitempty"`
}

type HIGHTTestVector struct {
	Algorithm string           `json:"algorithm"`
	Mode      string           `json:"mode"`
	TestMode  string           `json:"test_mode"`
	KeyBits   int              `json:"key_bits"`
	Encrypt   []HIGHTEncRecord `json:"encrypt"`
	Decrypt   []HIGHTDecRecord `json:"decrypt"`
}

// --- helpers ---

func randBytesHIGHT(n int) []byte {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return b
}

func minHIGHT(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fmtIntHIGHT(i int) string { return strconv.Itoa(i) }

func ivHexHIGHT(mode string, iv []byte) string {
	if strings.EqualFold(mode, "ECB") {
		return ""
	}
	return hex.EncodeToString(iv)
}

// setLeftmostBits returns a byte slice of length nBytes whose leftmost "bits" are set to 1.
func setLeftmostBitsHIGHT(nBytes, bits int) []byte {
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
func encryptOneHIGHT(mode string, blk cipher.Block, iv []byte, pt []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("unsupported HIGHT mode %q", mode)
	}
}

// --- generator ---

func GenerateHIGHTTestVectors(mode string, test string, p HIGHTGenParams) (HIGHTTestVector, error) {
	// HIGHT uses a 128-bit key and 64-bit block.
	if p.KeyBits != 128 {
		return HIGHTTestVector{}, errors.New("key_bits must be 128 for HIGHT")
	}
	mode = strings.ToUpper(strings.TrimSpace(mode))
	test = strings.ToUpper(strings.TrimSpace(test))

	var tmode HIGHTTestMode
	switch test {
	case "KAT":
		tmode = HIGHT_KAT
	case "MMT":
		tmode = HIGHT_MMT
	case "MCT":
		tmode = HIGHT_MCT
	default:
		return HIGHTTestVector{}, fmt.Errorf("unsupported test_mode %q", test)
	}

	switch mode {
	case "ECB", "CBC", "CFB", "OFB":
	default:
		return HIGHTTestVector{}, fmt.Errorf("unsupported HIGHT mode %q", mode)
	}

	keyLen := p.KeyBits / 8 // 16 bytes
	blockSize := 8          // 64-bit block

	var out HIGHTTestVector
	out.Algorithm = "HIGHT"
	out.Mode = mode
	out.TestMode = string(tmode)
	out.KeyBits = p.KeyBits

	switch tmode {
	case HIGHT_KAT:
		variant := strings.ToUpper(strings.TrimSpace(p.KatVariant))
		if variant == "" {
			return HIGHTTestVector{}, fmt.Errorf("KAT requires KatVariant (GFSBOX|KEYSBOX|VARKEY|VARTXT)")
		}
		zeroKey := make([]byte, keyLen)
		zeroIV := make([]byte, blockSize)

		switch variant {
		case "GFSBOX":
			blk, _ := gohight.NewCipher(zeroKey)
			for i := 0; i < p.Count; i++ {
				pt := randBytesHIGHT(blockSize)
				ct, _ := encryptOneHIGHT(mode, blk, zeroIV, pt)

				enc := HIGHTEncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(zeroKey),
					IVHex:     ivHexHIGHT(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := HIGHTDecRecord{
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
				key := randBytesHIGHT(keyLen)
				blk, _ := gohight.NewCipher(key)
				ct, _ := encryptOneHIGHT(mode, blk, zeroIV, pt)

				enc := HIGHTEncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivHexHIGHT(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := HIGHTDecRecord{
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
			limit := minHIGHT(p.Count, p.KeyBits) // up to 128
			for i := range limit {
				key := setLeftmostBitsHIGHT(keyLen, i+1)
				blk, _ := gohight.NewCipher(key)
				ct, _ := encryptOneHIGHT(mode, blk, zeroIV, pt)

				enc := HIGHTEncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivHexHIGHT(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := HIGHTDecRecord{
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
			blk, _ := gohight.NewCipher(key)
			limit := minHIGHT(p.Count, blockSize*8) // 64
			for i := range limit {
				pt := setLeftmostBitsHIGHT(blockSize, i+1)
				ct, _ := encryptOneHIGHT(mode, blk, zeroIV, pt)

				enc := HIGHTEncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivHexHIGHT(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := HIGHTDecRecord{
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
			return HIGHTTestVector{}, fmt.Errorf("unsupported HIGHT KAT variant %q", variant)
		}

	case HIGHT_MMT:
		loopCount := p.Count
		if loopCount > 10 {
			loopCount = 10
		}
		for i := 0; i < loopCount; i++ {
			key := randBytesHIGHT(keyLen)
			iv := randBytesHIGHT(blockSize)
			blk, _ := gohight.NewCipher(key)

			msg := randBytesHIGHT((i + 1) * blockSize)
			ct, _ := encryptOneHIGHT(mode, blk, iv, msg)

			enc := HIGHTEncRecord{
				Count:     i,
				KeyHex:    hex.EncodeToString(key),
				IVHex:     ivHexHIGHT(mode, iv),
				Plaintext: hex.EncodeToString(msg),
			}
			dec := HIGHTDecRecord{
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

	case HIGHT_MCT:
		// Monte Carlo-like test similar to AES style, adapted for 64-bit blocks and fixed 128-bit key.
		const inner = 1000

		key := randBytesHIGHT(keyLen)
		iv := randBytesHIGHT(blockSize)
		pt0 := randBytesHIGHT(blockSize)

		for i := 0; i < p.Count; i++ {
			keyRec := hex.EncodeToString(key)
			ivRec := hex.EncodeToString(iv)
			ptRec := hex.EncodeToString(pt0)

			blk, _ := gohight.NewCipher(key)
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

				enc := HIGHTEncRecord{Count: i, KeyHex: keyRec, Plaintext: ptRec}
				dec := HIGHTDecRecord{Count: i, KeyHex: keyRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < keyLen; k++ {
					key[k] ^= lastCT[k%blockSize]
				}
				copy(pt0, lastCT)

			case "CBC":
				iv_i := make([]byte, blockSize)
				copy(iv_i, iv)
				ct := make([]byte, blockSize)
				for j := range inner {
					if j == 0 {
						x := make([]byte, blockSize)
						for k := range blockSize {
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

				enc := HIGHTEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := HIGHTDecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := range keyLen {
					key[k] ^= lastCT[k%blockSize]
				}
				copy(iv, lastCT)  // next IV
				copy(pt0, prevCT) // next PT[0]

			case "OFB":
				iv_i := make([]byte, blockSize)
				copy(iv_i, iv)
				ct := make([]byte, blockSize)
				for j := range inner {
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

				enc := HIGHTEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := HIGHTDecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := range keyLen {
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

				enc := HIGHTEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := HIGHTDecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := range keyLen {
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
func (v HIGHTTestVector) ToTXT() string {
	var b strings.Builder
	b.WriteString("[ENCRYPT]\n\n")
	for _, r := range v.Encrypt {
		b.WriteString("COUNT = ")
		b.WriteString(fmtIntHIGHT(r.Count))
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
		b.WriteString(fmtIntHIGHT(r.Count))
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
