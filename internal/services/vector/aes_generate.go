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

func GenerateAESTestVectors(mode string, test string, p AESGenParams) (AESTestVector, error) {
	if p.Count <= 0 {
		p.Count = 10
	}
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
		key := make([]byte, keyLen) // zero key
		iv := make([]byte, 16)
		nonce := make([]byte, 12) // for GCM
		blk, _ := aes.NewCipher(key)

		for i := 0; i < p.Count; i++ {
			switch mode {
			case "ECB":
				pt := randBytes(16)
				ct := make([]byte, 16)
				blk.Encrypt(ct, pt)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CBC":
				pt := randBytes(16)
				ct := make([]byte, 16)
				cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, pt)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CFB":
				pt := randBytes(16)
				ct := make([]byte, len(pt))
				cipher.NewCFBEncrypter(blk, iv).XORKeyStream(ct, pt)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "OFB":
				pt := randBytes(16)
				ct := make([]byte, len(pt))
				cipher.NewOFB(blk, iv).XORKeyStream(ct, pt)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CTR":
				pt := randBytes(16)
				ct := make([]byte, len(pt))
				cipher.NewCTR(blk, iv).XORKeyStream(ct, pt)
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "GCM":
				pt := randBytes(16)
				aead, _ := cipher.NewGCM(blk)
				ct := aead.Seal(nil, nonce, pt, nil) // includes tag
				enc := EncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(nonce), Plaintext: hex.EncodeToString(pt)}
				dec := DecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}
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
		//nonce := make([]byte, 12)
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
				aead, _ := cipher.NewGCM(blk)
				nonceWork := make([]byte, 12)
				for j := 0; j < 1000; j++ {
					ct := aead.Seal(nil, nonceWork, pt, nil)
					copy(nonceWork, ct[:12])
					copy(pt, ct[:16])
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
