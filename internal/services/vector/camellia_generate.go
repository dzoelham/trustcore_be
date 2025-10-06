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
}

type CamEncRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"` // empty for ECB
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext,omitempty"`
}
type CamDecRecord struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"`
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
		// supported
	default:
		return CamTestVector{}, fmt.Errorf("unsupported Camellia mode %q", mode)
	}

	keyLen, err := camKeyLen(p.KeyBits)
	if err != nil {
		return CamTestVector{}, err
	}
	key := make([]byte, keyLen) // zero key for determinism-ish
	blk, err := camellia.NewCipher(key)
	if err != nil {
		return CamTestVector{}, err
	}

	var out CamTestVector
	out.Algorithm = "CAMELLIA"
	out.Mode = mode
	out.TestMode = string(tmode)
	out.KeyBits = p.KeyBits

	blockSize := blk.BlockSize() // 16
	iv := make([]byte, blockSize)
	nonce := make([]byte, 12) // for GCM

	switch tmode {
	case CAM_KAT:
		for i := 0; i < p.Count; i++ {
			pt := randBytes(blockSize)
			switch mode {
			case "ECB":
				ct := make([]byte, blockSize)
				blk.Encrypt(ct, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CBC":
				ct := make([]byte, blockSize)
				cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CFB":
				ct := make([]byte, blockSize)
				cipher.NewCFBEncrypter(blk, iv).XORKeyStream(ct, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "OFB":
				ct := make([]byte, blockSize)
				cipher.NewOFB(blk, iv).XORKeyStream(ct, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CTR":
				ct := make([]byte, blockSize)
				cipher.NewCTR(blk, iv).XORKeyStream(ct, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "GCM":
				aead, err := cipher.NewGCM(blk)
				if err != nil {
					return CamTestVector{}, err
				}
				ct := aead.Seal(nil, nonce, pt, nil) // includes tag
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(nonce), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}
		}

	case CAM_MMT:
		msg := randBytes(blockSize * 3)
		for i := 0; i < p.Count; i++ {
			switch mode {
			case "ECB":
				ct := make([]byte, len(msg))
				for off := 0; off < len(msg); off += blockSize {
					blk.Encrypt(ct[off:off+blockSize], msg[off:off+blockSize])
				}
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), Plaintext: hex.EncodeToString(msg[:blockSize])}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, Ciphertext: hex.EncodeToString(ct[:blockSize])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:blockSize])
					dec.Plaintext = hex.EncodeToString(msg[:blockSize])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CBC":
				ct := make([]byte, len(msg))
				cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, msg)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:blockSize])}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:blockSize])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:blockSize])
					dec.Plaintext = hex.EncodeToString(msg[:blockSize])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CFB":
				ct := make([]byte, len(msg))
				cipher.NewCFBEncrypter(blk, iv).XORKeyStream(ct, msg)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:blockSize])}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:blockSize])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:blockSize])
					dec.Plaintext = hex.EncodeToString(msg[:blockSize])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "OFB":
				ct := make([]byte, len(msg))
				cipher.NewOFB(blk, iv).XORKeyStream(ct, msg)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:blockSize])}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:blockSize])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:blockSize])
					dec.Plaintext = hex.EncodeToString(msg[:blockSize])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CTR":
				ct := make([]byte, len(msg))
				cipher.NewCTR(blk, iv).XORKeyStream(ct, msg)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:blockSize])}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:blockSize])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:blockSize])
					dec.Plaintext = hex.EncodeToString(msg[:blockSize])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "GCM":
				aead, err := cipher.NewGCM(blk)
				if err != nil {
					return CamTestVector{}, err
				}
				ct := aead.Seal(nil, nonce, msg, nil)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(nonce), Plaintext: hex.EncodeToString(msg[:blockSize])}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:blockSize])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:blockSize])
					dec.Plaintext = hex.EncodeToString(msg[:blockSize])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}
		}

	case CAM_MCT:
		for i := 0; i < p.Count; i++ {
			pt := randBytes(blockSize)
			ivWork := make([]byte, blockSize)
			switch mode {
			case "ECB":
				for j := 0; j < 1000; j++ {
					blk.Encrypt(pt, pt)
				}
				finalCT := make([]byte, blockSize)
				copy(finalCT, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, Ciphertext: hex.EncodeToString(finalCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(finalCT)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CBC":
				for j := 0; j < 1000; j++ {
					ct := make([]byte, blockSize)
					cipher.NewCBCEncrypter(blk, ivWork).CryptBlocks(ct, pt)
					copy(ivWork, ct)
					copy(pt, ct)
				}
				finalCT := make([]byte, blockSize)
				copy(finalCT, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(make([]byte, blockSize)), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(finalCT)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CFB":
				for j := 0; j < 1000; j++ {
					stream := cipher.NewCFBEncrypter(blk, ivWork)
					ct := make([]byte, blockSize)
					stream.XORKeyStream(ct, pt)
					copy(ivWork, ct)
					copy(pt, ct)
				}
				finalCT := make([]byte, blockSize)
				copy(finalCT, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(make([]byte, blockSize)), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(finalCT)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "OFB":
				for j := 0; j < 1000; j++ {
					stream := cipher.NewOFB(blk, ivWork)
					ct := make([]byte, blockSize)
					stream.XORKeyStream(ct, pt)
					copy(ivWork, ct)
					copy(pt, ct)
				}
				finalCT := make([]byte, blockSize)
				copy(finalCT, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(make([]byte, blockSize)), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(finalCT)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "CTR":
				for j := 0; j < 1000; j++ {
					stream := cipher.NewCTR(blk, ivWork)
					ct := make([]byte, blockSize)
					stream.XORKeyStream(ct, pt)
					copy(ivWork, ct[:blockSize])
					copy(pt, ct)
				}
				finalCT := make([]byte, blockSize)
				copy(finalCT, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(make([]byte, blockSize)), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(finalCT)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)

			case "GCM":
				aead, err := cipher.NewGCM(blk)
				if err != nil {
					return CamTestVector{}, err
				}
				nonceWork := make([]byte, 12)
				for j := 0; j < 1000; j++ {
					ct := aead.Seal(nil, nonceWork, pt, nil)
					copy(nonceWork, ct[:12])
					copy(pt, ct[:blockSize])
				}
				finalCT := make([]byte, blockSize)
				copy(finalCT, pt)
				enc := CamEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(nonceWork), Plaintext: hex.EncodeToString(pt)}
				dec := CamDecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
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
