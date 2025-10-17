// stream_snow2_generate.go
// SNOW 2.0 test-vector generator (KAT, MMT, MCT) with spec-accurate keystream.
// Package: vector — mirrors aes_generate.go style from this project.
package vector

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ------------------------------ Public types ------------------------------

type SNOW2TestMode string

const (
	SNOW2KAT SNOW2TestMode = "KAT"
	SNOW2MMT SNOW2TestMode = "MMT"
	SNOW2MCT SNOW2TestMode = "MCT"
)

type SNOW2GenParams struct {
	// Count: how many vectors to emit per section (Encrypt/Decrypt).
	// For MMT we FIX count at 10 (as requested) regardless of this value.
	Count int
	// KeyBits: 128 or 256
	KeyBits int
	// IncludeExpected: when true, compute ciphertext for Encrypt (and plaintext for Decrypt).
	IncludeExpected bool
}

// StdStreamRow is compatible with the EncRecord/DecRecord layout used elsewhere.
type StdStreamRow struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"`
	Plaintext  string `json:"plaintext,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	Answer     string `json:"answer,omitempty"` // optional: keystream or counterpart per mode
}

type SNOW2TestVector struct {
	Algorithm string         `json:"algorithm"`
	Mode      string         `json:"mode"`
	TestMode  SNOW2TestMode  `json:"test_mode"`
	Encrypt   []StdStreamRow `json:"encrypt"`
	Decrypt   []StdStreamRow `json:"decrypt"`
}

// GenerateSNOW2TestVectors creates SNOW 2.0 vectors.
// test ∈ {"KAT","MMT","MCT"} (case-insensitive).
//
// KAT: uses the official ISO/IEC 18033‑4 SNOW 2.0 initialization and produces
//
//	64 bytes of keystream per record for known-answer verification.
//
// MMT: FIXED 10 cases. For i=1..10, uses random Key/IV and a random plaintext that
//
//	grows with i (len = 16*i bytes).
//
// MCT: Monte Carlo Test. For each COUNT, runs 1000 iterations; on each iteration
//
//	the IV is incremented (big-endian) and the previous ciphertext feeds the next
//	plaintext (classic stream-cipher MCT style).
//
// For all modes, if IncludeExpected==true we compute the CIPHERTEXT of Encrypt rows and
// the PLAINTEXT of Decrypt rows (i.e., "vice versa").
func GenerateSNOW2TestVectors(test string, p SNOW2GenParams) (SNOW2TestVector, error) {
	tmode := SNOW2TestMode(strings.ToUpper(strings.TrimSpace(test)))
	if tmode == "" {
		tmode = SNOW2KAT
	}
	if p.KeyBits == 0 {
		p.KeyBits = 128
	}
	if p.KeyBits != 128 && p.KeyBits != 256 {
		return SNOW2TestVector{}, fmt.Errorf("invalid KeyBits %d: SNOW 2.0 supports 128 or 256", p.KeyBits)
	}

	out := SNOW2TestVector{
		Algorithm: "SNOW 2.0",
		Mode:      "STREAM",
		TestMode:  tmode,
	}

	switch tmode {
	case SNOW2KAT:
		// Use two simple known-answer-style cases per key size with all-zero IV and IV=(4,3,2,1).
		keyLens := []int{p.KeyBits / 8}
		ivs := []string{
			strings.Repeat("00", 16),           // (0,0,0,0)
			"00000004000000030000000200000001", // (IV3,IV2,IV1,IV0)=(4,3,2,1) big-endian words
		}
		count := p.Count
		if count <= 0 {
			count = 2
		}
		cur := 0
		for _, kl := range keyLens {
			for _, ivHex := range ivs {
				if cur > count {
					break
				}
				key := make([]byte, kl)
				if _, err := io.ReadFull(rand.Reader, key); err != nil {
					return SNOW2TestVector{}, err
				}
				// 64 bytes of keystream; plaintext = 64 zero bytes for KAT
				pt := make([]byte, 64)
				rowE := StdStreamRow{
					Count:     cur,
					KeyHex:    hex.EncodeToString(key),
					IVHex:     strings.ToLower(ivHex),
					Plaintext: hex.EncodeToString(pt),
				}
				if p.IncludeExpected {
					ks, err := snow2Keystream(key, mustDecodeHex(ivHex), len(pt))
					if err != nil {
						return SNOW2TestVector{}, err
					}
					ct := xorBytes(pt, ks)
					rowE.Ciphertext = hex.EncodeToString(ct)
				}
				out.Encrypt = append(out.Encrypt, rowE)

				// Decrypt side: provide only ciphertext; compute plaintext if requested.
				rowD := StdStreamRow{
					Count:      cur,
					KeyHex:     rowE.KeyHex,
					IVHex:      rowE.IVHex,
					Ciphertext: rowE.Ciphertext, // if IncludeExpected it is set; else leave empty
				}
				if p.IncludeExpected && rowE.Ciphertext != "" {
					ks, err := snow2Keystream(key, mustDecodeHex(ivHex), len(pt))
					if err != nil {
						return SNOW2TestVector{}, err
					}
					ctb, _ := hex.DecodeString(rowE.Ciphertext)
					rowD.Plaintext = hex.EncodeToString(xorBytes(ctb, ks))
				}
				out.Decrypt = append(out.Decrypt, rowD)
				cur++
			}
		}

	case SNOW2MMT:
		// FIX count at 10 regardless of p.Count.
		for i := range 10 {
			key := make([]byte, p.KeyBits/8)
			iv := make([]byte, 16)
			if _, err := io.ReadFull(rand.Reader, key); err != nil {
				return SNOW2TestVector{}, err
			}
			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
				return SNOW2TestVector{}, err
			}
			// PLAINTEXT is random and increases with COUNT: 16*i bytes.
			pt := make([]byte, 16*i)
			if _, err := io.ReadFull(rand.Reader, pt); err != nil {
				return SNOW2TestVector{}, err
			}

			rowE := StdStreamRow{
				Count:     i,
				KeyHex:    hex.EncodeToString(key),
				IVHex:     hex.EncodeToString(iv),
				Plaintext: hex.EncodeToString(pt),
			}
			if p.IncludeExpected {
				ks, err := snow2Keystream(key, iv, len(pt))
				if err != nil {
					return SNOW2TestVector{}, err
				}
				rowE.Ciphertext = hex.EncodeToString(xorBytes(pt, ks))
			}
			out.Encrypt = append(out.Encrypt, rowE)

			// Decrypt counterpart: use same key/iv, ciphertext from Encrypt.
			rowD := StdStreamRow{
				Count:      i,
				KeyHex:     rowE.KeyHex,
				IVHex:      rowE.IVHex,
				Ciphertext: rowE.Ciphertext,
			}
			if p.IncludeExpected && rowE.Ciphertext != "" {
				ctb, _ := hex.DecodeString(rowE.Ciphertext)
				ks, err := snow2Keystream(key, iv, len(ctb))
				if err != nil {
					return SNOW2TestVector{}, err
				}
				rowD.Plaintext = hex.EncodeToString(xorBytes(ctb, ks))
			}
			out.Decrypt = append(out.Decrypt, rowD)
		}

	case SNOW2MCT:
		keyBytes := p.KeyBits / 8
		if keyBytes == 0 {
			keyBytes = 16
		}
		n := p.Count
		if n <= 0 {
			n = 1
		}

		const mctRounds = 1000
		const blockBytes = 16 // 1 block per round for the loop below

		for i := 0; i < n; i++ {
			k := make([]byte, keyBytes)
			iv := make([]byte, 16)
			if _, err := rand.Read(k); err != nil {
				return SNOW2TestVector{}, err
			}
			if _, err := rand.Read(iv); err != nil {
				return SNOW2TestVector{}, err
			}

			// Starting plaintext for MCT (random 16 bytes); keep a copy so we can show it.
			pt := make([]byte, blockBytes)
			if _, err := rand.Read(pt); err != nil {
				return SNOW2TestVector{}, err
			}
			startPT := make([]byte, len(pt))
			copy(startPT, pt)

			// Run the Monte Carlo loop: 1000 rounds, feedback PT <- CT, IV increments each round.
			ct := make([]byte, len(pt))
			if p.IncludeExpected {
				tmpIV := make([]byte, len(iv))
				copy(tmpIV, iv)
				for r := 0; r < mctRounds; r++ {
					ks, err := snow2Keystream(k, tmpIV, len(pt))
					if err != nil {
						return SNOW2TestVector{}, err
					}
					for j := range pt {
						ct[j] = pt[j] ^ ks[j]
					}
					copy(pt, ct) // feedback
					incBE(tmpIV) // IV <- IV + 1 (big-endian)
				}
			}

			// ENCRYPT row: now we DO show the starting PLAINTEXT.
			rowE := StdStreamRow{
				Count:     i,
				KeyHex:    hex.EncodeToString(k),
				IVHex:     hex.EncodeToString(iv),      // initial IV (or keep final if you prefer)
				Plaintext: hex.EncodeToString(startPT), // ← show PLAINTEXT
				Ciphertext: func() string {
					if p.IncludeExpected {
						return hex.EncodeToString(ct)
					}
					return ""
				}(),
			}
			out.Encrypt = append(out.Encrypt, rowE)

			// DECRYPT row: mirror; when IncludeExpected, keep the same CT
			// (and you can also provide startPT as the "answer" if your format expects it).
			rowD := StdStreamRow{
				Count:      i,
				KeyHex:     rowE.KeyHex,
				IVHex:      rowE.IVHex,
				Ciphertext: rowE.Ciphertext,
			}
			if p.IncludeExpected {
				rowD.Plaintext = rowE.Plaintext // vice versa
			}
			out.Decrypt = append(out.Decrypt, rowD)
		}
		return out, nil

	default:
		return SNOW2TestVector{}, fmt.Errorf("unknown SNOW2 test mode %q", test)
	}

	return out, nil
}

// Pretty print (NIST-ish) — optional helper mirroring other generators.
func (v SNOW2TestVector) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Algorithm = %s\nMode = %s\nTest = %s\n\n", v.Algorithm, v.Mode, string(v.TestMode))
	emit := func(tag string, rows []StdStreamRow) {
		if len(rows) == 0 {
			return
		}
		fmt.Fprintf(&b, "[%s]\n", tag)
		for _, r := range rows {
			fmt.Fprintf(&b, "COUNT = %d\n", r.Count)
			fmt.Fprintf(&b, "KEY = %s\n", strings.ToUpper(r.KeyHex))
			fmt.Fprintf(&b, "IV = %s\n", strings.ToUpper(r.IVHex))
			if r.Plaintext != "" {
				fmt.Fprintf(&b, "PLAINTEXT = %s\n", strings.ToUpper(r.Plaintext))
			}
			if r.Ciphertext != "" {
				fmt.Fprintf(&b, "CIPHERTEXT = %s\n", strings.ToUpper(r.Ciphertext))
			}
			if r.Answer != "" {
				fmt.Fprintf(&b, "ANSWER = %s\n", strings.ToUpper(r.Answer))
			}
			b.WriteString("\n")
		}
	}
	emit("ENCRYPT", v.Encrypt)
	emit("DECRYPT", v.Decrypt)
	return b.String()
}

// ------------------------------ SNOW 2.0 core ------------------------------

// snow2KeystreamHex (legacy helper) returns hex-encoded keystream of n bytes for a given key/iv.
func snow2KeystreamHex(keyHex, ivHex string, n int, keyBits int) (string, error) {
	key, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil {
		return "", err
	}
	iv, err := hex.DecodeString(strings.TrimSpace(ivHex))
	if err != nil {
		return "", err
	}
	if keyBits != 128 && keyBits != 256 {
		return "", fmt.Errorf("invalid keyBits %d", keyBits)
	}
	if len(key) != keyBits/8 {
		return "", fmt.Errorf("key length mismatch: want %d bytes, got %d", keyBits/8, len(key))
	}
	if len(iv) != 16 {
		return "", fmt.Errorf("iv must be 16 bytes, got %d", len(iv))
	}
	ks, err := snow2Keystream(key, iv, n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ks), nil
}

// snow2Keystream generates n bytes of SNOW 2.0 keystream.
// Spec basis:
//   - FSM/LFSR/keystream equations per Kircanski & Youssef (2013) (eqs. (1)-(6)) —
//     Ft = (s15 + R1) XOR R2; R1' = s5 + R2; R2' = S(R1); s15' = α^{-1}s11 ⊕ s2 ⊕ α s0 (⊕ Ft during init t<32).
//   - α/α^{-1} multipliers per SNOW 3G spec (MULα/DIVα with c=0xA9) — identical LFSR in SNOW 2.0.
//   - S permutation equals SNOW 3G S1 (AES S-box + MixColumns style with 0x1B).
//
// These details are widely cited in the open literature.
func snow2Keystream(key, iv []byte, n int) ([]byte, error) {
	if len(iv) != 16 {
		return nil, errors.New("SNOW2: IV must be 16 bytes")
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("SNOW2: key must be 16 or 32 bytes")
	}

	// Convert key, IV into 32-bit big-endian words.
	readWords := func(b []byte) []uint32 {
		words := make([]uint32, 0, len(b)/4)
		for i := 0; i < len(b); i += 4 {
			words = append(words, binary.BigEndian.Uint32(b[i:i+4]))
		}
		return words
	}
	K := readWords(key)
	IV := readWords(iv)

	// Initial state population (big-endian words), using 0xFFFFFFFF for "1".
	const allOnes uint32 = 0xFFFFFFFF
	var s [16]uint32
	if len(K) == 4 {
		// 128-bit key mapping (eq. (3) in Kircanski-Youssef).
		s[15] = K[3] ^ IV[0]
		s[14] = K[2]
		s[13] = K[1]
		s[12] = K[0] ^ IV[1]
		s[11] = K[3] ^ allOnes
		s[10] = K[2] ^ allOnes ^ IV[2]
		s[9] = K[1] ^ allOnes ^ IV[3]
		s[8] = K[0] ^ allOnes
		s[7] = K[3]
		s[6] = K[2]
		s[5] = K[1]
		s[4] = K[0]
		s[3] = K[3] ^ allOnes
		s[2] = K[2] ^ allOnes
		s[1] = K[1] ^ allOnes
		s[0] = K[0] ^ allOnes
	} else {
		// 256-bit key mapping (eq. (6)).
		s[15] = K[7] ^ IV[0]
		s[14] = K[6]
		s[13] = K[5]
		s[12] = K[4] ^ IV[1]
		s[11] = K[3]
		s[10] = K[2] ^ IV[2]
		s[9] = K[1] ^ IV[3]
		s[8] = K[0]
		s[7] = K[7] ^ allOnes
		s[6] = K[6] ^ allOnes
		s[5] = K[5] ^ allOnes
		s[4] = K[4] ^ allOnes
		s[3] = K[3] ^ allOnes
		s[2] = K[2] ^ allOnes
		s[1] = K[1] ^ allOnes
		s[0] = K[0] ^ allOnes
	}

	var R1, R2 uint32 // FSM registers, start at 0

	// Helper: LFSR step (initMode: include Ft).
	lfsrStep := func(initMode bool, Ft uint32) {
		// v = (s0 << 8) ⊕ MULα(msb(s0)) ⊕ s2 ⊕ (s11 >> 8) ⊕ DIVα(lsb(s11)) [⊕ Ft if init].
		// Implemented per byte-permutation form from SNOW 3G spec (works for SNOW 2.0 as LFSR is identical).
		b0 := byte(s[0] >> 24)
		b1 := byte(s[0] >> 16)
		b2 := byte(s[0] >> 8)
		// b3 := byte(s[0])
		e0 := byte(s[11] >> 24)
		e1 := byte(s[11] >> 16)
		e2 := byte(s[11] >> 8)
		e3 := byte(s[11])

		var v uint32
		v ^= (uint32(b1) << 24) | (uint32(b2) << 16) | (uint32(byte(s[0])) << 8) // (s0 << 8)
		v ^= mulAlpha(b0)
		v ^= s[2]
		v ^= (uint32(e0) << 16) | (uint32(e1) << 8) | uint32(e2) // (s11 >> 8)
		v ^= divAlpha(e3)
		if initMode {
			v ^= Ft
		}

		// Shift register
		for i := 0; i < 15; i++ {
			s[i] = s[i+1]
		}
		s[15] = v
	}

	// Run 33 init steps, with Ft injected for t<32.
	for t := 0; t <= 32; t++ {
		Ft := uint32(uint64(s[15]+R1)&0xffffffff) ^ R2
		// Update FSM: R1' = s5 + R2; R2' = S(R1)
		oldR1 := R1
		R1 = uint32(uint64(s[5]+R2) & 0xffffffff)
		R2 = Sperm(oldR1)
		// LFSR
		lfsrStep(t < 32, Ft)
	}

	// Keystream generation
	ks := make([]byte, 0, n)
	for len(ks) < n {
		Ft := uint32(uint64(s[15]+R1)&0xffffffff) ^ R2
		z := s[0] ^ Ft
		// Output z as big-endian bytes
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], z)
		need := n - len(ks)
		if need >= 4 {
			ks = append(ks, buf[:]...)
		} else {
			ks = append(ks, buf[:need]...)
		}
		// Update FSM and then LFSR (keystream mode: no Ft injection)
		oldR1 := R1
		R1 = uint32(uint64(s[5]+R2) & 0xffffffff)
		R2 = Sperm(oldR1)
		lfsrStep(false, 0)
	}

	return ks[:n], nil
}

// ------------------------------ Math helpers ------------------------------

// xorBytes returns a^b for len(b)>=len(a); allocates a new slice.
func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		panic(err)
	}
	return b
}

func incBE(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
}

// ------------------------------ S permutation (SNOW 2.0 == SNOW 3G S1) ------------------------------

// Sperm is the 32->32 permutation used in SNOW 2.0 FSM, equal to SNOW 3G's S1.
// It applies the AES S-box to each byte and then a MixColumn-like linear map
// using MULx(_,0x1B).
func Sperm(w uint32) uint32 {
	w0 := byte(w >> 24)
	w1 := byte(w >> 16)
	w2 := byte(w >> 8)
	w3 := byte(w)

	s0 := aesSBox[w0]
	s1 := aesSBox[w1]
	s2 := aesSBox[w2]
	s3 := aesSBox[w3]

	r0 := mulx(s0, 0x1B) ^ s1 ^ s2 ^ mulx(s3, 0x1B) ^ s3
	r1 := mulx(s0, 0x1B) ^ s0 ^ mulx(s1, 0x1B) ^ s2 ^ s3
	r2 := s0 ^ mulx(s1, 0x1B) ^ s1 ^ mulx(s2, 0x1B) ^ s3
	r3 := s0 ^ s1 ^ mulx(s2, 0x1B) ^ mulx(s3, 0x1B) ^ s2

	return (uint32(r0) << 24) | (uint32(r1) << 16) | (uint32(r2) << 8) | uint32(r3)
}

// mulx implements the SNOW/AES gf(2^8) multiply-by-x with reduction by c (0x1B here).
func mulx(v, c byte) byte {
	if v&0x80 != 0 {
		return ((v << 1) ^ c) & 0xFF
	}
	return (v << 1) & 0xFF
}

// ------------------------------ α and α^{-1} multipliers ------------------------------

// mulAlpha implements MULα(c) (SNOW 3G spec), returning a 32-bit word composed of 4 bytes:
// [ x^23(c) | x^245(c) | x^48(c) | x^239(c) ]
func mulAlpha(c byte) uint32 {
	b0 := mulxpow(c, 23, 0xA9)
	b1 := mulxpow(c, 245, 0xA9)
	b2 := mulxpow(c, 48, 0xA9)
	b3 := mulxpow(c, 239, 0xA9)
	return (uint32(b0) << 24) | (uint32(b1) << 16) | (uint32(b2) << 8) | uint32(b3)
}

// divAlpha implements DIVα(c) == MUL_{α^{-1}}(c), returning [ x^16(c) | x^39(c) | x^6(c) | x^64(c) ].
func divAlpha(c byte) uint32 {
	b0 := mulxpow(c, 16, 0xA9)
	b1 := mulxpow(c, 39, 0xA9)
	b2 := mulxpow(c, 6, 0xA9)
	b3 := mulxpow(c, 64, 0xA9)
	return (uint32(b0) << 24) | (uint32(b1) << 16) | (uint32(b2) << 8) | uint32(b3)
}

func mulxpow(v byte, n int, c byte) byte {
	out := v
	for range n {
		out = mulx(out, c)
	}
	return out
}

// ------------------------------ AES S-box ------------------------------

// AES S-box table (Rijndael). Taken from FIPS-197.
var aesSBox = [256]byte{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
}
