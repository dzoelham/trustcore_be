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

	gomisty1 "github.com/deatil/go-cryptobin/cipher/misty1"
)

type MISTY1TestMode string

const (
	MISTY1_KAT MISTY1TestMode = "KAT"
	MISTY1_MMT MISTY1TestMode = "MMT"
	MISTY1_MCT MISTY1TestMode = "MCT"
)

type MISTY1GenParams struct {
	KeyBits         int
	Count           int
	IncludeExpected bool
	// Only used when test_mode == KAT. Allowed: GFSBOX | KEYSBOX | VARKEY | VARTXT
	KatVariant string
}

type MISTY1EncRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // empty for ECB
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext,omitempty"`
}
type MISTY1DecRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // empty for ECB
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext,omitempty"`
}

type MISTY1TestVector struct {
	Algorithm string             `json:"algorithm"`
	Mode      string             `json:"mode"`
	TestMode  string             `json:"test_mode"`
	KeyBits   int                `json:"key_bits"`
	Encrypt   []MISTY1EncRecord  `json:"encrypt"`
	Decrypt   []MISTY1DecRecord  `json:"decrypt"`
}

// --- helpers ---

func randBytesMISTY(n int) []byte {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return b
}

func minMISTY(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fmtIntMISTY(i int) string { return strconv.Itoa(i) }

func ivHexMISTY(mode string, iv []byte) string {
	if strings.EqualFold(mode, "ECB") {
		return ""
	}
	return hex.EncodeToString(iv)
}

// setLeftmostBits returns a byte slice of length nBytes whose leftmost "bits" are set to 1.
func setLeftmostBitsMISTY(nBytes, bits int) []byte {
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
// For stream modes (CFB/OFB/CTR) the len equals len(pt).
func encryptOneMISTY(mode string, blk cipher.Block, iv []byte, pt []byte) ([]byte, error) {
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
	case "CTR":
		ct := make([]byte, len(pt))
		cipher.NewCTR(blk, iv).XORKeyStream(ct, pt)
		return ct, nil
	default:
		return nil, fmt.Errorf("unsupported MISTY1 mode %q", mode)
	}
}

// --- generator ---

func GenerateMISTY1TestVectors(mode string, test string, p MISTY1GenParams) (MISTY1TestVector, error) {
	// MISTY1 uses a 128-bit key and 64-bit block.
	if p.KeyBits != 128 {
		return MISTY1TestVector{}, errors.New("key_bits must be 128 for MISTY1")
	}
	mode = strings.ToUpper(strings.TrimSpace(mode))
	test = strings.ToUpper(strings.TrimSpace(test))

	var tmode MISTY1TestMode
	switch test {
	case "KAT":
		tmode = MISTY1_KAT
	case "MMT":
		tmode = MISTY1_MMT
	case "MCT":
		tmode = MISTY1_MCT
	default:
		return MISTY1TestVector{}, fmt.Errorf("unsupported test_mode %q", test)
	}

	switch mode {
	case "ECB", "CBC", "CFB", "OFB", "CTR":
	default:
		return MISTY1TestVector{}, fmt.Errorf("unsupported MISTY1 mode %q", mode)
	}

	keyLen := p.KeyBits / 8 // 16
	blockSize := 8          // MISTY1 block size

	var out MISTY1TestVector
	out.Algorithm = "MISTY1"
	out.Mode = mode
	out.TestMode = string(tmode)
	out.KeyBits = p.KeyBits

	switch tmode {
	case MISTY1_KAT:
		variant := strings.ToUpper(strings.TrimSpace(p.KatVariant))
		if variant == "" {
			return MISTY1TestVector{}, fmt.Errorf("KAT requires KatVariant (GFSBOX|KEYSBOX|VARKEY|VARTXT)")
		}
		zeroKey := make([]byte, keyLen)
		zeroIV := make([]byte, blockSize)

		switch variant {
		case "GFSBOX":
			blk, _ := gomisty1.NewCipher(zeroKey)
			for i := 0; i < p.Count; i++ {
				pt := randBytesMISTY(blockSize)
				ct, _ := encryptOneMISTY(mode, blk, zeroIV, pt)

				enc := MISTY1EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(zeroKey),
					IVHex:     ivHexMISTY(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := MISTY1DecRecord{
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
				key := randBytesMISTY(keyLen)
				blk, _ := gomisty1.NewCipher(key)
				ct, _ := encryptOneMISTY(mode, blk, zeroIV, pt)

				enc := MISTY1EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivHexMISTY(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := MISTY1DecRecord{
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
			limit := minMISTY(p.Count, p.KeyBits) // up to 128
			for i := 0; i < limit; i++ {
				key := setLeftmostBitsMISTY(keyLen, i+1)
				blk, _ := gomisty1.NewCipher(key)
				ct, _ := encryptOneMISTY(mode, blk, zeroIV, pt)

				enc := MISTY1EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivHexMISTY(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := MISTY1DecRecord{
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
			blk, _ := gomisty1.NewCipher(key)
			limit := minMISTY(p.Count, blockSize*8) // 64
			for i := 0; i < limit; i++ {
				pt := setLeftmostBitsMISTY(blockSize, i+1)
				ct, _ := encryptOneMISTY(mode, blk, zeroIV, pt)

				enc := MISTY1EncRecord{
					Count:     i,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     ivHexMISTY(mode, zeroIV),
					Plaintext: hex.EncodeToString(pt),
				}
				dec := MISTY1DecRecord{
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
			return MISTY1TestVector{}, fmt.Errorf("unsupported MISTY1 KAT variant %q", variant)
		}

	case MISTY1_MMT:
		loopCount := p.Count
		if loopCount > 10 {
			loopCount = 10
		}
		for i := 0; i < loopCount; i++ {
			key := randBytesMISTY(keyLen)
			iv := randBytesMISTY(blockSize)
			blk, _ := gomisty1.NewCipher(key)

			msg := randBytesMISTY((i + 1) * blockSize)
			ct, _ := encryptOneMISTY(mode, blk, iv, msg)

			enc := MISTY1EncRecord{
				Count:     i,
				KeyHex:    hex.EncodeToString(key),
				IVHex:     ivHexMISTY(mode, iv),
				Plaintext: hex.EncodeToString(msg),
			}
			dec := MISTY1DecRecord{
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

	case MISTY1_MCT:
		// Monte Carlo-like test mirroring AES style but adapted for 64-bit blocks, 128-bit key.
		const inner = 1000

		key := randBytesMISTY(keyLen)
		iv := randBytesMISTY(blockSize)
		pt0 := randBytesMISTY(blockSize)

		for i := 0; i < p.Count; i++ {
			keyRec := hex.EncodeToString(key)
			ivRec := hex.EncodeToString(iv)
			ptRec := hex.EncodeToString(pt0)

			blk, _ := gomisty1.NewCipher(key)
			lastCT := make([]byte, blockSize) // CT[j]
			prevCT := make([]byte, blockSize) // CT[j-1]

			pt := make([]byte, blockSize)
			copy(pt, pt0)

			switch mode {
			case "ECB":
				ct := make([]byte, blockSize)
				for j := 0; j < inner; j++ {
					blk.Encrypt(ct, pt)
					copy(pt, ct)          // PT[j+1] = CT[j]
					copy(prevCT, lastCT)  // track CT[j-1]
					copy(lastCT, ct)      // CT[j]
				}

				enc := MISTY1EncRecord{Count: i, KeyHex: keyRec, Plaintext: ptRec}
				dec := MISTY1DecRecord{Count: i, KeyHex: keyRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				// Update key: XOR 16-byte key with lastCT repeated to 16 bytes.
				for k := 0; k < keyLen; k++ { key[k] ^= lastCT[k%blockSize] }
				copy(pt0, lastCT)

			case "CBC":
				iv_i := make([]byte, blockSize); copy(iv_i, iv)
				ct := make([]byte, blockSize)
				for j := 0; j < inner; j++ {
					if j == 0 {
						// CT[0] = E_K(PT[0] XOR IV[i]); PT[1] = IV[i]
						x := make([]byte, blockSize)
						for k := 0; k < blockSize; k++ { x[k] = pt[k] ^ iv_i[k] }
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

				enc := MISTY1EncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := MISTY1DecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < keyLen; k++ { key[k] ^= lastCT[k%blockSize] }
				copy(iv, lastCT)  // next IV
				copy(pt0, prevCT) // next PT[0]

			case "OFB":
				iv_i := make([]byte, blockSize); copy(iv_i, iv)
				ct := make([]byte, blockSize)
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

				enc := MISTY1EncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := MISTY1DecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < keyLen; k++ { key[k] ^= lastCT[k%blockSize] }
				copy(iv, lastCT)
				copy(pt0, prevCT)

			case "CFB":
				iv_i := make([]byte, blockSize); copy(iv_i, iv)
				ct := make([]byte, blockSize)
				for j := 0; j < inner; j++ {
					if j == 0 {
						stream := cipher.NewCFBEncrypter(blk, iv_i)
						stream.XORKeyStream(ct, pt) // first block
						copy(pt, iv_i)              // PT[1] = IV[i]
					} else {
						blk.Encrypt(ct, pt)         // CT[j] = E_K(PT[j]) (legacy/simple)
						copy(pt, prevCT)            // PT[j+1] = CT[j-1]
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}

				enc := MISTY1EncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := MISTY1DecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < keyLen; k++ { key[k] ^= lastCT[k%blockSize] }
				copy(iv, lastCT)
				copy(pt0, prevCT)

			case "CTR":
				ivWork := make([]byte, blockSize); copy(ivWork, iv)
				msg := make([]byte, blockSize); copy(msg, pt0)
				for j := 0; j < inner; j++ {
					stream := cipher.NewCTR(blk, ivWork)
					tmp := make([]byte, blockSize)
					stream.XORKeyStream(tmp, msg)
					copy(ivWork, tmp[:blockSize])
					copy(msg, tmp)
				}
				last := make([]byte, blockSize); copy(last, msg)

				enc := MISTY1EncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := MISTY1DecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(last)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(last)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

				for k := 0; k < keyLen; k++ { key[k] ^= last[k%blockSize] }
				copy(iv, last)
				copy(pt0, last)
			}
		}
	}

	return out, nil
}

// Optional formatter similar to NIST .rsp style
func (v MISTY1TestVector) ToTXT() string {
	var b strings.Builder
	b.WriteString("[ENCRYPT]\n\n")
	for _, r := range v.Encrypt {
		b.WriteString("COUNT = ")
		b.WriteString(fmtIntMISTY(r.Count))
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
		b.WriteString(fmtIntMISTY(r.Count))
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
