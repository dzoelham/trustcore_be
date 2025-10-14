
package vector

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/aead/camellia" // go get github.com/aead/camellia
)

type CamTestMode string

const (
	CAM_KAT CamTestMode = "KAT"
	CAM_MMT CamTestMode = "MMT"
	CAM_MCT CamTestMode = "MCT"
)

type CamGenParams struct {
	KeyBits         int
	Count           int
	IncludeExpected bool
	// Only used when test_mode == KAT. Allowed: GFSBOX | KEYSBOX | VARKEY | VARTXT
	KatVariant      string
}

type CamEncRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // nonce/IV (empty for ECB)
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext,omitempty"`
}
type CamDecRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // nonce/IV (empty for ECB)
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext,omitempty"`
}

type CamTestVector struct {
	Algorithm string         `json:"algorithm"`
	Mode      string         `json:"mode"`
	TestMode  string         `json:"test_mode"`
	KeyBits   int            `json:"key_bits"`
	Encrypt   []CamEncRecord `json:"encrypt"`
	Decrypt   []CamDecRecord `json:"decrypt"`
}

func camKeyLen(bits int) (int, error) {
	switch bits {
	case 128, 192, 256:
		return bits / 8, nil
	default:
		return 0, errors.New("key_bits must be 128/192/256 for Camellia")
	}
}

// encrypt one message according to mode (mirrors AES encryptOne).
// For ECB/CBC the returned ciphertext is 16 bytes.
// For stream modes (CFB/OFB/CTR) the len equals len(pt).
// For GCM it returns ciphertext||tag.
func encryptOneCam(mode string, blk cipher.Block, iv []byte, nonce []byte, pt []byte) ([]byte, error) {
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
		aead, err := cipher.NewGCM(blk) // Camellia has 128-bit block size, so GCM is valid
		if err != nil {
			return nil, err
		}
		return aead.Seal(nil, nonce, pt, nil), nil
	default:
		return nil, fmt.Errorf("unsupported Camellia mode %q", mode)
	}
}

func GenerateCamelliaTestVectors(mode string, test string, p CamGenParams) (CamTestVector, error) {
	if p.Count <= 0 {
		p.Count = 10
	}
	mode = strings.ToUpper(strings.TrimSpace(mode))
	test = strings.ToUpper(strings.TrimSpace(test))

	var tmode CamTestMode
	switch test {
	case "KAT":
		tmode = CAM_KAT
	case "MMT":
		tmode = CAM_MMT
	case "MCT":
		tmode = CAM_MCT
	default:
		return CamTestVector{}, fmt.Errorf("unsupported test_mode %q", test)
	}

	switch mode {
	case "ECB", "CBC", "CFB", "OFB", "CTR", "GCM":
		// ok
	default:
		return CamTestVector{}, fmt.Errorf("unsupported Camellia mode %q", mode)
	}

	keyLen, err := camKeyLen(p.KeyBits)
	if err != nil {
		return CamTestVector{}, err
	}

	var out CamTestVector
	out.Algorithm = "CAMELLIA"
	out.Mode = mode
	out.TestMode = string(tmode)
	out.KeyBits = p.KeyBits

	switch tmode {
	case CAM_KAT:
		variant := strings.ToUpper(strings.TrimSpace(p.KatVariant))
		if variant == "" {
			variant = "GFSBOX"
		}
		zeroKey := make([]byte, keyLen)
		zeroIV := make([]byte, 16)
		zeroNonce := make([]byte, 12)

		blk, err := camellia.NewCipher(zeroKey)
		if err != nil { return CamTestVector{}, err }

		switch variant {
		case "GFSBOX":
			for i := 0; i < p.Count; i++ {
				pt := randBytes(16)
				ct, _ := encryptOneCam(mode, blk, zeroIV, zeroNonce, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(zeroKey), IVHex: ivOrNonceHex(mode, zeroIV, zeroNonce), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected { enc.Ciphertext = hex.EncodeToString(ct); dec.Plaintext = hex.EncodeToString(pt) }
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}

		case "KEYSBOX":
			pt := make([]byte, 16)
			for i := 0; i < p.Count; i++ {
				key := randBytes(keyLen)
				blk, _ := camellia.NewCipher(key)
				ct, _ := encryptOneCam(mode, blk, zeroIV, zeroNonce, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: ivOrNonceHex(mode, zeroIV, zeroNonce), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected { enc.Ciphertext = hex.EncodeToString(ct); dec.Plaintext = hex.EncodeToString(pt) }
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}

		case "VARKEY":
			pt := make([]byte, 16)
			limit := min(p.Count, p.KeyBits)
			for i := range limit {
				key := setLeftmostBits(keyLen, i+1)
				blk, _ := camellia.NewCipher(key)
				ct, _ := encryptOneCam(mode, blk, zeroIV, zeroNonce, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: ivOrNonceHex(mode, zeroIV, zeroNonce), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected { enc.Ciphertext = hex.EncodeToString(ct); dec.Plaintext = hex.EncodeToString(pt) }
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}

		case "VARTXT":
			key := make([]byte, keyLen)
			blk, _ := camellia.NewCipher(key)
			limit := min(p.Count, 128)
			for i := range limit {
				pt := setLeftmostBits(16, i+1)
				ct, _ := encryptOneCam(mode, blk, zeroIV, zeroNonce, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: ivOrNonceHex(mode, zeroIV, zeroNonce), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected { enc.Ciphertext = hex.EncodeToString(ct); dec.Plaintext = hex.EncodeToString(pt) }
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}
		default:
			return CamTestVector{}, fmt.Errorf("unsupported Camellia KAT variant %q", variant)
		}

	case CAM_MMT:
		// MMT: plaintext grows with COUNT (cap at 10); fresh random key and IV/nonce per COUNT
		loopCount := p.Count
		if loopCount > 10 { loopCount = 10 }
		for i := 0; i < loopCount; i++ {
			key := randBytes(keyLen)
			iv := randBytes(16)
			nonce := randBytes(12)
			blk, _ := camellia.NewCipher(key)
			msg := randBytes((i+1) * 16)
			ct, _ := encryptOneCam(mode, blk, iv, nonce, msg)
			enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: ivOrNonceHex(mode, iv, nonce), Plaintext: hex.EncodeToString(msg)}
			dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
			if p.IncludeExpected { enc.Ciphertext = hex.EncodeToString(ct); dec.Plaintext = hex.EncodeToString(msg) }
			out.Encrypt = append(out.Encrypt, enc)
			out.Decrypt = append(out.Decrypt, dec)
		}

	case CAM_MCT:
		// Mirror AESAVS-style MCT logic used in aes_generate.go
		const inner = 1000
		key := randBytes(keyLen)
		iv := randBytes(16)
		pt0 := randBytes(16)
		for i := 0; i < p.Count; i++ {
			keyRec := hex.EncodeToString(key)
			ivRec := hex.EncodeToString(iv)
			ptRec := hex.EncodeToString(pt0)
			blk, _ := camellia.NewCipher(key)
			lastCT := make([]byte, 16)
			prevCT := make([]byte, 16)
			pt := make([]byte, 16); copy(pt, pt0)

			switch mode {
			case "ECB":
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					blk.Encrypt(ct, pt)
					copy(pt, ct)
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}
				enc := CamEncRecord{Count: i, KeyHex: keyRec, Plaintext: ptRec}
				dec := CamDecRecord{Count: i, KeyHex: keyRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected { enc.Ciphertext = hex.EncodeToString(lastCT); dec.Plaintext = ptRec }
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
				copy(pt0, lastCT)

			case "CBC":
				iv_i := make([]byte, 16); copy(iv_i, iv)
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					if j == 0 {
						x := make([]byte, 16)
						for k := 0; k < 16; k++ { x[k] = pt[k] ^ iv_i[k] }
						blk.Encrypt(ct, x)
						copy(pt, iv_i)
					} else {
						blk.Encrypt(ct, pt)
						copy(pt, prevCT)
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}
				enc := CamEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := CamDecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected { enc.Ciphertext = hex.EncodeToString(lastCT); dec.Plaintext = ptRec }
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

			case "OFB":
				iv_i := make([]byte, 16); copy(iv_i, iv)
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					if j == 0 {
						stream := cipher.NewOFB(blk, iv_i)
						stream.XORKeyStream(ct, pt)
						copy(pt, iv_i)
					} else {
						blk.Encrypt(ct, pt)
						copy(pt, prevCT)
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}
				enc := CamEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := CamDecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected { enc.Ciphertext = hex.EncodeToString(lastCT); dec.Plaintext = ptRec }
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

			case "CFB":
				iv_i := make([]byte, 16); copy(iv_i, iv)
				ct := make([]byte, 16)
				for j := 0; j < inner; j++ {
					if j == 0 {
						stream := cipher.NewCFBEncrypter(blk, iv_i)
						stream.XORKeyStream(ct, pt)
						copy(pt, iv_i)
					} else {
						blk.Encrypt(ct, pt)
						copy(pt, prevCT)
					}
					copy(prevCT, lastCT)
					copy(lastCT, ct)
				}
				enc := CamEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := CamDecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(lastCT)}
				if p.IncludeExpected { enc.Ciphertext = hex.EncodeToString(lastCT); dec.Plaintext = ptRec }
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
				enc := CamEncRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Plaintext: ptRec}
				dec := CamDecRecord{Count: i, KeyHex: keyRec, IVHex: ivRec, Ciphertext: hex.EncodeToString(last)}
				if p.IncludeExpected { enc.Ciphertext = hex.EncodeToString(last); dec.Plaintext = ptRec }
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
				for k := 0; k < min(len(key), 16); k++ { key[k] ^= last[k] }
				copy(iv, last)
				copy(pt0, last)

			case "GCM":
				aead, _ := cipher.NewGCM(blk)
				nonce := make([]byte, 12)
				msg := make([]byte, 16); copy(msg, pt0)
				var last []byte
				for j := 0; j < inner; j++ {
					last = aead.Seal(nil, nonce, msg, nil)
					copy(nonce, last[:min(12, len(last))])
					copy(msg, last[:min(16, len(last))])
				}
				enc := CamEncRecord{Count: i, KeyHex: keyRec, IVHex: hex.EncodeToString(nonce), Plaintext: ptRec}
				dec := CamDecRecord{Count: i, KeyHex: keyRec, IVHex: hex.EncodeToString(nonce), Ciphertext: hex.EncodeToString(last)}
				if p.IncludeExpected { enc.Ciphertext = hex.EncodeToString(last); dec.Plaintext = ptRec }
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
				for k := 0; k < min(len(key), 16) && k < len(last); k++ { key[k] ^= last[k] }
				if len(last) >= 16 { copy(pt0, last[:16]) }
			}
		}
	}
	return out, nil
}

// TXT helper (rsp-like)
func (v CamTestVector) ToTXT() string {
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
