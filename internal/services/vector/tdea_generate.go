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

func tdeaKey(keyBits int) ([]byte, error) {
	switch keyBits {
	case 112: // 2-key TDEA (K1 K2 K1)
		k := randBytes(16)              // K1(8) + K2(8)
		return append(k, k[:8]...), nil // K1 K2 K1 => 24 bytes
	case 168: // 3-key TDEA (K1 K2 K3)
		return randBytes(24), nil
	default:
		return nil, errors.New("key_bits must be 112 or 168 for TDEA")
	}
}

func new3DESCipher(key []byte) (cipher.Block, error) {
	// des.NewTripleDESCipher requires len(key) == 24
	if len(key) != 24 {
		return nil, errors.New("3DES key must be 24 bytes")
	}
	return des.NewTripleDESCipher(key)
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

	key, err := tdeaKey(p.KeyBits)
	if err != nil {
		return TDEATestVector{}, err
	}
	blk, err := new3DESCipher(key)
	if err != nil {
		return TDEATestVector{}, err
	}

	var out TDEATestVector
	out.Algorithm = "TDEA"
	out.Mode = mode
	out.TestMode = string(tmode)
	out.KeyBits = p.KeyBits

	blockSize := blk.BlockSize() // 8
	iv := make([]byte, blockSize)

	switch tmode {
	case TDEA_KAT:
		for i := 0; i < p.Count; i++ {
			pt := randBytes(blockSize)
			switch mode {
			case "ECB":
				ct := make([]byte, blockSize)
				blk.Encrypt(ct, pt)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			case "CBC":
				ct := make([]byte, blockSize)
				cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, pt)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			case "CFB":
				ct := make([]byte, blockSize)
				cipher.NewCFBEncrypter(blk, iv).XORKeyStream(ct, pt)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			case "OFB":
				ct := make([]byte, blockSize)
				cipher.NewOFB(blk, iv).XORKeyStream(ct, pt)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			case "CTR":
				ct := make([]byte, blockSize)
				cipher.NewCTR(blk, iv).XORKeyStream(ct, pt)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct)}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct)
					dec.Plaintext = hex.EncodeToString(pt)
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}
		}

	case TDEA_MMT:
		msg := randBytes(blockSize * 3)
		for i := 0; i < p.Count; i++ {
			switch mode {
			case "ECB":
				ct := make([]byte, len(msg))
				for off := 0; off < len(msg); off += blockSize {
					blk.Encrypt(ct[off:off+blockSize], msg[off:off+blockSize])
				}
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), Plaintext: hex.EncodeToString(msg[:blockSize])}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, Ciphertext: hex.EncodeToString(ct[:blockSize])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:blockSize])
					dec.Plaintext = hex.EncodeToString(msg[:blockSize])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			case "CBC":
				ct := make([]byte, len(msg))
				cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, msg)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:blockSize])}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:blockSize])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:blockSize])
					dec.Plaintext = hex.EncodeToString(msg[:blockSize])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			case "CFB":
				ct := make([]byte, len(msg))
				cipher.NewCFBEncrypter(blk, iv).XORKeyStream(ct, msg)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:blockSize])}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:blockSize])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:blockSize])
					dec.Plaintext = hex.EncodeToString(msg[:blockSize])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			case "OFB":
				ct := make([]byte, len(msg))
				cipher.NewOFB(blk, iv).XORKeyStream(ct, msg)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:blockSize])}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:blockSize])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:blockSize])
					dec.Plaintext = hex.EncodeToString(msg[:blockSize])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			case "CTR":
				ct := make([]byte, len(msg))
				cipher.NewCTR(blk, iv).XORKeyStream(ct, msg)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(iv), Plaintext: hex.EncodeToString(msg[:blockSize])}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(ct[:blockSize])}
				if p.IncludeExpected {
					enc.Ciphertext = hex.EncodeToString(ct[:blockSize])
					dec.Plaintext = hex.EncodeToString(msg[:blockSize])
				}
				out.Encrypt = append(out.Encrypt, enc)
				out.Decrypt = append(out.Decrypt, dec)
			}
		}

	case TDEA_MCT:
		for i := 0; i < p.Count; i++ {
			pt := randBytes(blockSize)
			ivWork := make([]byte, blockSize) // zero iv seed
			switch mode {
			case "ECB":
				for j := 0; j < 1000; j++ {
					blk.Encrypt(pt, pt)
				}
				finalCT := make([]byte, blockSize)
				copy(finalCT, pt)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, Ciphertext: hex.EncodeToString(finalCT)}
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
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(make([]byte, blockSize)), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
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
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(make([]byte, blockSize)), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
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
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(make([]byte, blockSize)), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
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
					copy(ivWork, ct)
					copy(pt, ct)
				}
				finalCT := make([]byte, blockSize)
				copy(finalCT, pt)
				enc := TDEAEncRecord{Count: i, KeyHex: hex.EncodeToString(key), IVHex: hex.EncodeToString(make([]byte, blockSize)), Plaintext: hex.EncodeToString(pt)}
				dec := TDEADecRecord{Count: i, KeyHex: enc.KeyHex, IVHex: enc.IVHex, Ciphertext: hex.EncodeToString(finalCT)}
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
