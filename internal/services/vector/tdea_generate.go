package vector

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type TDEATestMode string

const (
	TDEA_KAT TDEATestMode = "KAT"
	TDEA_MMT TDEATestMode = "MMT"
	TDEA_MCT TDEATestMode = "MCT"
)

type TDEAGenParams struct {
	KeyBits         int // 112 (2-key) or 168 (3-key)
	Count           int
	IncludeExpected bool
	// Only used when test_mode == KAT. Allowed: GFSBOX | KEYSBOX | VARKEY | VARTXT
	KatVariant string
}

type TDEAEncRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // empty for ECB
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext,omitempty"`
}

type TDEADecRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext,omitempty"`
}

type TDEATestVector struct {
	Algorithm string          `json:"algorithm"`
	Mode      string          `json:"mode"`
	TestMode  string          `json:"test_mode"`
	KeyBits   int             `json:"key_bits"`
	Encrypt   []TDEAEncRecord `json:"encrypt"`
	Decrypt   []TDEADecRecord `json:"decrypt"`
}

// Build a 24-byte 3DES key from KeyBits.
// 112 => 2-key TDEA (K1‖K2‖K1), 168 => 3-key (K1‖K2‖K3).
func tdeaKeyMaterial(keyBits int) (int, error) {
	switch keyBits {
	case 112:
		return 16, nil // unique bytes; expanded to 24 as K1‖K2‖K1
	case 168:
		return 24, nil
	default:
		return 0, errors.New("key_bits must be 112 or 168 for TDEA")
	}
}

func expand2KeyTo3Key(k16 []byte) []byte {
	// K1(8)‖K2(8) -> K1‖K2‖K1
	out := make([]byte, 24)
	copy(out[0:8], k16[0:8])
	copy(out[8:16], k16[8:16])
	copy(out[16:24], k16[0:8])
	return out
}

func normalizeKeyForBits(key []byte, keyBits int) []byte {
	if keyBits == 112 {
		// keep first 16 bytes as K1‖K2 and mirror K1 as K3
		if len(key) < 16 {
			k := make([]byte, 16)
			copy(k, key)
			return expand2KeyTo3Key(k)
		}
		return expand2KeyTo3Key(key[:16])
	}
	// 168-bit: ensure 24 bytes
	k := make([]byte, 24)
	copy(k, key)
	return k
}

func new3DESCipher(key []byte) (cipher.Block, error) {
	if len(key) != 24 {
		return nil, errors.New("3DES key must be 24 bytes")
	}
	return des.NewTripleDESCipher(key)
}

// Single-message encryption matching mode semantics.
func encryptOneTDEA(mode string, blk cipher.Block, iv []byte, pt []byte) ([]byte, error) {
	mode = strings.ToUpper(mode)
	bs := blk.BlockSize() // 8
	switch mode {
	case "ECB":
		if len(pt)%bs != 0 {
			return nil, fmt.Errorf("ECB requires full blocks: got %d", len(pt))
		}
		ct := make([]byte, len(pt))
		for off := 0; off < len(pt); off += bs {
			blk.Encrypt(ct[off:off+bs], pt[off:off+bs])
		}
		return ct, nil
	case "CBC":
		if len(pt)%bs != 0 {
			return nil, fmt.Errorf("CBC requires full blocks: got %d", len(pt))
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
		return nil, fmt.Errorf("unsupported TDEA mode %q", mode)
	}
}

func GenerateTDEATestVectors(mode string, test string, p TDEAGenParams) (TDEATestVector, error) {
	if p.Count <= 0 {
		p.Count = 10
	}
	mode = strings.ToUpper(strings.TrimSpace(mode))
	test = strings.ToUpper(strings.TrimSpace(test))

	var tmode TDEATestMode
	switch test {
	case "KAT":
		tmode = TDEA_KAT
	case "MMT":
		tmode = TDEA_MMT
	case "MCT":
		tmode = TDEA_MCT
	default:
		return TDEATestVector{}, fmt.Errorf("unsupported test_mode %q", test)
	}

	switch mode {
	case "ECB", "CBC", "CFB", "OFB", "CTR":
	default:
		return TDEATestVector{}, fmt.Errorf("unsupported TDEA mode %q", mode)
	}

	kmLen, err := tdeaKeyMaterial(p.KeyBits)
	if err != nil {
		return TDEATestVector{}, err
	}

	var out TDEATestVector
	out.Algorithm = "TDEA"
	out.Mode = mode
	out.TestMode = string(tmode)
	out.KeyBits = p.KeyBits

	// 3DES parameters
	bs := 8
	zeroIV := make([]byte, bs)

	switch tmode {
	case TDEA_KAT:
		variant := strings.ToUpper(strings.TrimSpace(p.KatVariant))
		if variant == "" {
			return TDEATestVector{}, fmt.Errorf("KatVariant must be specified for KAT (allowed: GFSBOX, KEYSBOX, VARKEY, VARTXT)")
		}

		switch variant {
		case "GFSBOX":
			// random PT, zero key & IV
			keyMat := make([]byte, kmLen) // all-zero material
			key := normalizeKeyForBits(keyMat, p.KeyBits)
			blk, _ := new3DESCipher(key)
			for i := 0; i < p.Count; i++ {
				pt := randBytes(bs)
				ct, _ := encryptOneTDEA(mode, blk, zeroIV, pt)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(zeroIV), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				if mode == "ECB" {
					enc.IVHex, dec.IVHex = "", ""
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}

		case "KEYSBOX":
			// random key & IV, zero PT
			pt := make([]byte, bs)
			for i := 0; i < p.Count; i++ {
				rawKey := randBytes(kmLen)
				key := normalizeKeyForBits(rawKey, p.KeyBits)
				iv := randBytes(bs)
				blk, _ := new3DESCipher(key)
				ct, _ := encryptOneTDEA(mode, blk, iv, pt)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				if mode == "ECB" {
					enc.IVHex, dec.IVHex = "", ""
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}

		case "VARKEY":
			// PT all-zero, keys with increasing leftmost bits set
			pt := make([]byte, bs)
			limit := min(p.Count, p.KeyBits) // one bit per step
			for i := range limit {
				// Build key material of kmLen bytes with (i+1) leftmost bits set
				mat := setLeftmostBits(kmLen, i+1)
				key := normalizeKeyForBits(mat, p.KeyBits)
				blk, _ := new3DESCipher(key)
				ct, _ := encryptOneTDEA(mode, blk, zeroIV, pt)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(zeroIV), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				if mode == "ECB" {
					enc.IVHex, dec.IVHex = "", ""
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}

		case "VARTXT":
			// Key all-zero, PT with increasing leftmost bits set
			mat := make([]byte, kmLen)
			key := normalizeKeyForBits(mat, p.KeyBits)
			blk, _ := new3DESCipher(key)
			limit := min(p.Count, 64) // 64-bit blocks
			for i := range limit {
				pt := setLeftmostBits(bs, i+1)
				ct, _ := encryptOneTDEA(mode, blk, zeroIV, pt)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(zeroIV), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				if mode == "ECB" {
					enc.IVHex, dec.IVHex = "", ""
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}
		default:
			return TDEATestVector{}, fmt.Errorf("unsupported TDEA KAT variant %q", variant)
		}

	case TDEA_MMT:
		// PLAINTEXT grows per COUNT (cap at 10). Fresh key/IV per COUNT.
		loopCount := 10
		for i := 0; i < loopCount; i++ {
			rawKey := randBytes(kmLen)
			key := normalizeKeyForBits(rawKey, p.KeyBits)
			blk, _ := new3DESCipher(key)
			iv := randBytes(bs)
			msg := randBytes((i + 1) * bs)
			ct, _ := encryptOneTDEA(mode, blk, iv, msg)
			enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg)}
			dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
			if p.IncludeExpected {
				enc.Ciphertext = hex.EncodeToString(ct)
				dec.Plaintext = hex.EncodeToString(msg)
			}
			if mode == "ECB" {
				enc.IVHex, dec.IVHex = "", ""
			}
			out.Encrypt = append(out.Encrypt, enc)
			out.Decrypt = append(out.Decrypt, dec)
		}

	case TDEA_MCT:
		// AESAVS/CAVP-style Monte Carlo: 1000 inner iterations; mutate key each outer loop.
		const inner = 1000
		// Seed with random key/IV/PT
		rawKey := randBytes(kmLen)
		key := normalizeKeyForBits(rawKey, p.KeyBits)
		iv := randBytes(bs)
		pt0 := randBytes(bs)

		for i := 0; i < p.Count; i++ {
			blk, _ := new3DESCipher(key)
			keyRec := hex.EncodeToString(key)
			ivRec := hex.EncodeToString(iv)
			ptRec := hex.EncodeToString(pt0)

			lastCT := make([]byte, bs)
			prevCT := make([]byte, bs)
			pt := make([]byte, bs)
			copy(pt, pt0)

			switch mode {
			case "ECB":
				ct := make([]byte, bs)
				for j := 0; j < inner; j++ {
					blk.Encrypt(ct, pt)
					copy(pt, ct)
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}
				enc := TDEAEncRecord{Count: i, KeyHex: keyRec, Plaintext: ptRec}
				dec := TDEADecRecord{Count: i, KeyHex: keyRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CBC":
				ivWork := make([]byte, bs)
				copy(ivWork, iv)
				ct := make([]byte, bs)
				for j := 0; j < inner; j++ {
					// standard CBC step on single block
					x := make([]byte, bs)
					for k := 0; k < bs; k++ {
						if j == 0 {
							x[k] = pt[k] ^ ivWork[k]
						} else {
							x[k] = pt[k]
						}
					}
					blk.Encrypt(ct, x)
					if j == 0 {
						copy(pt, ivWork)
					} else {
						copy(pt, prevCT)
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}
				enc := TDEAEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := TDEADecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
				copy(iv, lastCT)
				copy(pt0, prevCT)

			case "CFB":
				ivWork := make([]byte, bs)
				copy(ivWork, iv)
				ct := make([]byte, bs)
				for j := 0; j < inner; j++ {
					if j == 0 {
						stream := cipher.NewCFBEncrypter(blk, ivWork)
						stream.XORKeyStream(ct, pt)
						copy(pt, ivWork)
					} else {
						blk.Encrypt(ct, pt)
						copy(pt, prevCT)
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}
				enc := TDEAEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := TDEADecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
				copy(iv, lastCT)
				copy(pt0, prevCT)

			case "OFB":
				ivWork := make([]byte, bs)
				copy(ivWork, iv)
				ct := make([]byte, bs)
				for j := 0; j < inner; j++ {
					if j == 0 {
						stream := cipher.NewOFB(blk, ivWork)
						stream.XORKeyStream(ct, pt)
						copy(pt, ivWork)
					} else {
						blk.Encrypt(ct, pt)
						copy(pt, prevCT)
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}
				enc := TDEAEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := TDEADecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(lastCT)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
				copy(iv, lastCT)
				copy(pt0, prevCT)

			case "CTR":
				ivWork := make([]byte, bs)
				copy(ivWork, iv)
				msg := make([]byte, bs)
				copy(msg, pt0)
				for j := 0; j < inner; j++ {
					stream := cipher.NewCTR(blk, ivWork)
					tmp := make([]byte, bs)
					stream.XORKeyStream(tmp, msg)
					copy(ivWork, tmp[:bs])
					copy(msg, tmp)
				}
				last := make([]byte, bs)
				copy(last, msg)
				enc := TDEAEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := TDEADecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(last)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(last)
					dec.Plaintext = ptRec
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
				copy(iv, last)
				copy(pt0, last)
			}

			// === Key mutation per outer COUNT ===
			// XOR the 24-byte key with last ciphertext repeated as needed.
			repeat := make([]byte, 24)
			for k := 0; k < 24; k++ {
				repeat[k] = lastCT[k%bs]
			}
			for k := 0; k < 24; k++ {
				key[k] ^= repeat[k]
			}
			// For 2-key variants, enforce K1‖K2‖K1 structure.
			if p.KeyBits == 112 {
				copy(key[16:24], key[0:8])
			}
		}
	}

	return out, nil
}

// TXT formatter (rsp-like)
func (v TDEATestVector) ToTXT() string {
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
