package vector

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

type AESCBCRecord struct {
	Count int
	Key   []byte
	IV    []byte
	PT    []byte
	CT    []byte
	Mode  string // ENCRYPT or DECRYPT
}

type AESCBCMismatch struct {
	Count    int    `json:"count"`
	Mode     string `json:"mode"`
	Expected string `json:"expected"`
	Got      string `json:"got"`
}

type AESCBCValidationResult struct {
	Total    int              `json:"total"`
	Passed   int              `json:"passed"`
	Failed   int              `json:"failed"`
	Failures []AESCBCMismatch `json:"failures,omitempty"`
}

func ParseAESCBCVectorFile(r io.Reader) ([]AESCBCRecord, error) {
	var recs []AESCBCRecord
	sc := bufio.NewScanner(r)
	section := ""
	var cur AESCBCRecord

	flush := func() {
		if cur.Key != nil || cur.IV != nil || cur.PT != nil || cur.CT != nil {
			cur.Mode = strings.ToUpper(section)
			recs = append(recs, cur)
			cur = AESCBCRecord{}
		}
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			section = strings.ToUpper(strings.Trim(line, "[]"))
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])

		switch k {
		case "COUNT":
			flush()
			fmt.Sscanf(v, "%d", &cur.Count)
		case "KEY":
			cur.Key, _ = hex.DecodeString(v)
		case "IV":
			cur.IV, _ = hex.DecodeString(v)
		case "PLAINTEXT":
			cur.PT, _ = hex.DecodeString(v)
		case "CIPHERTEXT":
			cur.CT, _ = hex.DecodeString(v)
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return recs, nil
}

func ValidateAESCBC(recs []AESCBCRecord) (AESCBCValidationResult, error) {
	res := AESCBCValidationResult{Total: len(recs)}
	for _, r := range recs {
		block, err := aes.NewCipher(r.Key)
		if err != nil {
			return res, err
		}
		bs := block.BlockSize()
		if len(r.IV) != bs {
			return res, fmt.Errorf("bad IV size at COUNT=%d", r.Count)
		}

		switch strings.ToUpper(r.Mode) {
		case "ENCRYPT":
			if len(r.PT)%bs != 0 {
				return res, fmt.Errorf("PT not block-aligned at COUNT=%d", r.Count)
			}
			out := make([]byte, len(r.PT))
			cipher.NewCBCEncrypter(block, r.IV).CryptBlocks(out, r.PT)
			if bytes.Equal(out, r.CT) {
				res.Passed++
			} else {
				res.Failed++
				res.Failures = append(res.Failures, AESCBCMismatch{
					Count:    r.Count,
					Mode:     "ENCRYPT",
					Expected: hex.EncodeToString(r.CT),
					Got:      hex.EncodeToString(out),
				})
			}

		case "DECRYPT":
			if len(r.CT)%bs != 0 {
				return res, fmt.Errorf("CT not block-aligned at COUNT=%d", r.Count)
			}
			out := make([]byte, len(r.CT))
			cipher.NewCBCDecrypter(block, r.IV).CryptBlocks(out, r.CT)
			if bytes.Equal(out, r.PT) {
				res.Passed++
			} else {
				res.Failed++
				res.Failures = append(res.Failures, AESCBCMismatch{
					Count:    r.Count,
					Mode:     "DECRYPT",
					Expected: hex.EncodeToString(r.PT),
					Got:      hex.EncodeToString(out),
				})
			}

		default:
			return res, fmt.Errorf("unknown section/mode at COUNT=%d", r.Count)
		}
	}
	return res, nil
}
