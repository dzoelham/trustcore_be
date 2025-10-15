// stream_mugi_generate.go
package vector

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

/* ===================== Public API & Types ===================== */

type MUGIGenParams struct {
	Count           int
	IncludeExpected bool
}

type MUGITestVector struct {
	Algorithm string      `json:"algorithm"`
	Mode      string      `json:"mode"`      // "STREAM"
	TestMode  string      `json:"test_mode"` // "KAT" / "MMT" / "MCT" / etc.
	KeyBits   int         `json:"key_bits"`  // 128
	Encrypt   []EncRecord `json:"encrypt"`
	Decrypt   []DecRecord `json:"decrypt"`
}

// GenerateMUGITestVectors:
//   - KAT: emits the two spec Appendix C examples (answers included when IncludeExpected).
//   - MMT: generates Count cases with growing plaintexts; if IncludeExpected -> compute C = P ⊕ KS.
//   - MCT: for each COUNT, produce 1000 keystream words (8000 bytes) against zero-PT unless provided;
//     if IncludeExpected -> set ciphertext/plaintext by XORing with KS.
//   - Any other tmode: generate Count random (Key, IV), 64B zero plaintext; include answers when requested.
func GenerateMUGITestVectors(test string, p MUGIGenParams) (MUGITestVector, error) {
	t := strings.ToUpper(strings.TrimSpace(test))
	n := p.Count
	if n <= 0 {
		n = 1
	}

	out := MUGITestVector{
		Algorithm: "MUGI",
		Mode:      "STREAM",
		TestMode:  t,
		KeyBits:   128,
	}

	switch t {
	case "KAT":
		emitKAT(&out, p.IncludeExpected) // Official vectors; answers when requested. :contentReference[oaicite:1]{index=1}
		return out, nil

	case "MMT":
		// Growing plaintext per COUNT: 8, 16, 24, ... bytes
		for i := 0; i < n; i++ {
			keyHex, _ := randHex(16)
			ivHex, _ := randHex(16)
			ptLen := 8 * (i + 1)      // bytes
			pt := make([]byte, ptLen) // default all-zero; caller can change later if needed
			ptHex := hex.EncodeToString(pt)

			enc := EncRecord{Count: i, KeyHex: keyHex, IVHex: ivHex, Plaintext: ptHex}
			dec := DecRecord{Count: i, KeyHex: keyHex, IVHex: ivHex, Ciphertext: ""}

			if p.IncludeExpected {
				ks := mugiKeystreamHex(keyHex, ivHex, ptLen)
				ct := xorHex(ptHex, ks)
				enc.Ciphertext = ct
				dec.Plaintext = ptHex
				dec.Ciphertext = ct
			}

			out.Encrypt = append(out.Encrypt, enc)
			out.Decrypt = append(out.Decrypt, dec)
		}
		return out, nil

	case "MCT":
		// Simple Monte Carlo for stream ciphers:
		// - For each COUNT, initialize once, then generate 1000 × 64-bit outputs (8000 bytes).
		// - Use zero-PT of that length; answers filled when requested.
		const mctRounds = 1000
		totalBytes := 8 * mctRounds
		for i := 0; i < n; i++ {
			keyHex, _ := randHex(16)
			ivHex, _ := randHex(16)

			pt := make([]byte, totalBytes) // zero-PT
			ptHex := hex.EncodeToString(pt)

			enc := EncRecord{Count: i, KeyHex: keyHex, IVHex: ivHex, Plaintext: ptHex}
			dec := DecRecord{Count: i, KeyHex: keyHex, IVHex: ivHex, Ciphertext: ""}

			if p.IncludeExpected {
				ks := mugiKeystreamHex(keyHex, ivHex, totalBytes)
				ct := xorHex(ptHex, ks)
				enc.Ciphertext = ct
				dec.Plaintext = ptHex
				dec.Ciphertext = ct
			}

			out.Encrypt = append(out.Encrypt, enc)
			out.Decrypt = append(out.Decrypt, dec)
		}
		return out, nil

	default:
		// Generic: Count random (Key, IV), 64B zero-PT
		for i := 0; i < n; i++ {
			keyHex, _ := randHex(16)
			ivHex, _ := randHex(16)
			pt := make([]byte, 64)
			ptHex := hex.EncodeToString(pt)

			enc := EncRecord{Count: i, KeyHex: keyHex, IVHex: ivHex, Plaintext: ptHex}
			dec := DecRecord{Count: i, KeyHex: keyHex, IVHex: ivHex}

			if p.IncludeExpected {
				ks := mugiKeystreamHex(keyHex, ivHex, len(pt))
				ct := xorHex(ptHex, ks)
				enc.Ciphertext = ct
				dec.Plaintext = ptHex
				dec.Ciphertext = ct
			}

			out.Encrypt = append(out.Encrypt, enc)
			out.Decrypt = append(out.Decrypt, dec)
		}
		return out, nil
	}
}

/* ===================== KAT (spec vectors) ===================== */

func emitKAT(v *MUGITestVector, include bool) {
	join := func(words ...string) string { return strings.ToLower(strings.Join(words, "")) }

	// Example 1 (all zeros) — Appendix C
	ex1Key := strings.Repeat("00", 16)
	ex1IV := strings.Repeat("00", 16)
	ex1KS := join(
		"c76e14e70836e6b6", "cb0e9c5a0bf03e1e",
		"0acf9af49ebe6d67", "d5726e374b1397ac",
		"dac3838528c1e592", "8a132730ef2bb752",
		"bd6229599f6d9ac2", "7c04760502f1e182",
	) // 8×64-bit outputs concatenated. :contentReference[oaicite:2]{index=2}
	zeroPT := strings.Repeat("00", 8*8) // 64 bytes

	enc1 := EncRecord{Count: 0, KeyHex: ex1Key, IVHex: ex1IV, Plaintext: zeroPT}
	dec1 := DecRecord{Count: 0, KeyHex: ex1Key, IVHex: ex1IV, Ciphertext: ex1KS}
	if include {
		enc1.Ciphertext = ex1KS
		dec1.Plaintext = zeroPT
	}
	v.Encrypt = append(v.Encrypt, enc1)
	v.Decrypt = append(v.Decrypt, dec1)

	// Example 2 (00..0f key, f0..00 IV) — Appendix C
	var key2 bytesBuilder
	for i := 0; i < 16; i++ {
		key2.writeByteHex(byte(i))
	}
	ex2Key := key2.String()
	ex2IV := "f0e0d0c0b0a090807060504030201000"
	ex2KS := join(
		"bc62430614b79b71", "71a66681c35542de",
		"7aba5b4fb80e82d7", "0b96982890b6e143",
		"4930b5d033157f46", "b96ed8499a282645",
		"dbeb1ef16d329b15", "34a9192c4ddcf34e",
	) // :contentReference[oaicite:3]{index=3}

	enc2 := EncRecord{Count: 1, KeyHex: ex2Key, IVHex: ex2IV, Plaintext: zeroPT}
	dec2 := DecRecord{Count: 1, KeyHex: ex2Key, IVHex: ex2IV, Ciphertext: ex2KS}
	if include {
		enc2.Ciphertext = ex2KS
		dec2.Plaintext = zeroPT
	}
	v.Encrypt = append(v.Encrypt, enc2)
	v.Decrypt = append(v.Decrypt, dec2)
}

/* ===================== Minimal MUGI Core (per spec) ===================== */

type mugi struct {
	a [3]uint64  // a0,a1,a2 (state)
	b [16]uint64 // buffer b0..b15
}

const (
	c0 = 0x6A09E667F3BCC908 // √2  · 2^64  (init)  :contentReference[oaicite:4]{index=4}
	c1 = 0xBB67AE8584CAA73B // √3  · 2^64  (rho)   :contentReference[oaicite:5]{index=5}
	c2 = 0x3C6EF372FE94F82B // √5  · 2^64  (rho)   :contentReference[oaicite:6]{index=6}
)

func (m *mugi) init(key [2]uint64, iv [2]uint64) {
	// ---- Step 1: set a from key, fill b by 16 iterations of rho with b=0
	m.a[0] = key[0]
	m.a[1] = key[1]
	m.a[2] = rotl64(key[0], 7) ^ rotr64(key[1], 7) ^ c0

	// 16 iterations of rho with b=0, store a(t+1).a0 into b[15-i]
	var tmp mugi
	tmp = *m
	for i := 0; i < 16; i++ {
		tmp.rhoZero()        // uses b=0 path
		m.b[15-i] = tmp.a[0] // b15-i = (ρ^{i+1}(a,0))_0  :contentReference[oaicite:7]{index=7}
	}

	// Mix a(K) = ρ^16(a,0)
	*m = tmp

	// ---- Step 2: add IV into a(K)
	m.a[0] ^= iv[0]
	m.a[1] ^= iv[1]
	m.a[2] ^= (rotl64(iv[0], 7) ^ rotr64(iv[1], 7) ^ c0)

	// Mix again by 16 rounds of rho with b=0 → a = ρ^16(a(K,I),0)
	for i := 0; i < 16; i++ {
		m.rhoZero()
	}

	// ---- Step 3: 16 rounds of full Update (rho+lambda) with current a,b
	for i := 0; i < 16; i++ {
		m.round() // Out is not used during mixing
	}
}

// Generate nb bytes of keystream; Out[t] = a2 at the beginning of each round. :contentReference[oaicite:8]{index=8}
func (m *mugi) gen(nb int) []byte {
	if nb <= 0 {
		return nil
	}
	out := make([]byte, 0, nb)
	for len(out) < nb {
		// Output 8 bytes = a2 (big-endian)
		out = appendUint64BE(out, m.a[2])
		m.round()
	}
	return out[:nb]
}

func (m *mugi) round() {
	// Save current a for lambda parameter
	a0 := m.a[0]

	// ρ(a,b): two F-functions + constants, per spec (Fig.2). :contentReference[oaicite:9]{index=9}
	newA0 := m.a[1]
	newA1 := m.a[2] ^ F(m.a[1], m.b[4]) ^ c1
	newA2 := m.a[0] ^ F(m.a[1], rotl64(m.b[10], 17)) ^ c2
	m.a[0], m.a[1], m.a[2] = newA0, newA1, newA2

	// λ(b,a): linear buffer update with specials at j∈{0,4,10}. :contentReference[oaicite:10]{index=10}
	var nb [16]uint64
	for j := 0; j < 16; j++ { // default shift
		nb[j] = m.b[(j+15)&15]
	}
	nb[0] = m.b[15] ^ a0
	nb[4] = m.b[3] ^ m.b[7]
	nb[10] = m.b[9] ^ rotl64(m.b[13], 32)
	m.b = nb
}

// rho with b=0 used during key/IV mixing
func (m *mugi) rhoZero() {
	newA0 := m.a[1]
	newA1 := m.a[2] ^ F(m.a[1], 0) ^ c1
	newA2 := m.a[0] ^ F(m.a[1], 0) ^ c2 // b10=0 -> rotl(0,17)=0
	m.a[0], m.a[1], m.a[2] = newA0, newA1, newA2
}

/* ===================== F-function (AES S-box + MDS) ===================== */

// F(X,B): bytewise S-box, AES MixColumns (MDS), and byte shuffling. :contentReference[oaicite:11]{index=11}
func F(x, b uint64) uint64 {
	o := x ^ b
	var O [8]byte
	putU64BE(&O, o)

	// S-box on each byte (AES S-box from Appendix A). :contentReference[oaicite:12]{index=12}
	for i := 0; i < 8; i++ {
		O[i] = sbox[O[i]]
	}
	// Split into PH (0..3) and PL (4..7), apply AES MixColumns to each 4-byte lane. :contentReference[oaicite:13]{index=13}
	QH0, QH1, QH2, QH3 := mix4(O[0], O[1], O[2], O[3])
	QL4, QL5, QL6, QL7 := mix4(O[4], O[5], O[6], O[7])

	// Byte shuffling: Y = Q4 Q5 Q2 Q3 Q0 Q1 Q6 Q7. :contentReference[oaicite:14]{index=14}
	Y := [8]byte{QL4, QL5, QH2, QH3, QH0, QH1, QL6, QL7}
	return getU64BE(Y)
}

func mix4(x0, x1, x2, x3 byte) (y0, y1, y2, y3 byte) {
	// AES MixColumns with matrix [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] on GF(2^8). :contentReference[oaicite:15]{index=15}
	y0 = xtime2[x0] ^ xtime3[x1] ^ x2 ^ x3
	y1 = x0 ^ xtime2[x1] ^ xtime3[x2] ^ x3
	y2 = x0 ^ x1 ^ xtime2[x2] ^ xtime3[x3]
	y3 = xtime3[x0] ^ x1 ^ x2 ^ xtime2[x3]
	return
}

/* ===================== Helpers & Tables ===================== */

func mugiKeystreamHex(keyHex, ivHex string, n int) string {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 16 {
		panic("bad key hex")
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil || len(iv) != 16 {
		panic("bad iv hex")
	}
	k0 := getU64BEfrom(key[:8])
	k1 := getU64BEfrom(key[8:])
	i0 := getU64BEfrom(iv[:8])
	i1 := getU64BEfrom(iv[8:])

	var m mugi
	m.init([2]uint64{k0, k1}, [2]uint64{i0, i1})
	ks := m.gen(n)
	return hex.EncodeToString(ks)
}

func xorHex(aHex, bHex string) string {
	a, _ := hex.DecodeString(aHex)
	b, _ := hex.DecodeString(bHex)
	if len(b) < len(a) {
		panic("keystream too short")
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return hex.EncodeToString(out)
}

func randHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

type bytesBuilder struct{ sb strings.Builder }

func (b *bytesBuilder) writeByteHex(x byte) {
	const hex = "0123456789abcdef"
	b.sb.WriteByte(hex[x>>4])
	b.sb.WriteByte(hex[x&0x0f])
}
func (b *bytesBuilder) String() string { return b.sb.String() }

func rotl64(x uint64, n uint) uint64 { return (x << n) | (x >> (64 - n)) }
func rotr64(x uint64, n uint) uint64 { return (x >> n) | (x << (64 - n)) }

func appendUint64BE(dst []byte, v uint64) []byte {
	return append(dst,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}
func putU64BE(b *[8]byte, v uint64) {
	(*b)[0] = byte(v >> 56)
	(*b)[1] = byte(v >> 48)
	(*b)[2] = byte(v >> 40)
	(*b)[3] = byte(v >> 32)
	(*b)[4] = byte(v >> 24)
	(*b)[5] = byte(v >> 16)
	(*b)[6] = byte(v >> 8)
	(*b)[7] = byte(v)
}
func getU64BE(b [8]byte) uint64 {
	return (uint64(b[0]) << 56) | (uint64(b[1]) << 48) | (uint64(b[2]) << 40) | (uint64(b[3]) << 32) |
		(uint64(b[4]) << 24) | (uint64(b[5]) << 16) | (uint64(b[6]) << 8) | uint64(b[7])
}
func getU64BEfrom(b []byte) uint64 {
	return (uint64(b[0]) << 56) | (uint64(b[1]) << 48) | (uint64(b[2]) << 40) | (uint64(b[3]) << 32) |
		(uint64(b[4]) << 24) | (uint64(b[5]) << 16) | (uint64(b[6]) << 8) | uint64(b[7])
}

// === AES S-box (Appendix A) and xtime tables for 2x,3x (2x ^ x) ===  :contentReference[oaicite:16]{index=16}
var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var xtime2, xtime3 [256]byte

func init() {
	for i := 0; i < 256; i++ {
		x := byte(i)
		xtime2[i] = xtime(x)
		xtime3[i] = xtime2[i] ^ x
	}
}

func xtime(x byte) byte {
	if x&0x80 != 0 {
		return (x << 1) ^ 0x1b
	}
	return x << 1
}

/* ===================== Optional TXT formatter ===================== */

func (v MUGITestVector) ToTXT() string {
	var b strings.Builder
	b.WriteString("[ENCRYPT]\n\n")
	for _, r := range v.Encrypt {
		fmt.Fprintf(&b, "COUNT = %d\nKEY = %s\n", r.Count, strings.ToLower(r.KeyHex))
		if r.IVHex != "" {
			fmt.Fprintf(&b, "IV = %s\n", strings.ToLower(r.IVHex))
		}
		fmt.Fprintf(&b, "PLAINTEXT = %s\n", strings.ToLower(r.Plaintext))
		if r.Ciphertext != "" {
			fmt.Fprintf(&b, "\nCIPHERTEXT = %s\n", strings.ToLower(r.Ciphertext))
		}
		b.WriteString("\n")
	}
	b.WriteString("[DECRYPT]\n\n")
	for _, r := range v.Decrypt {
		fmt.Fprintf(&b, "COUNT = %d\nKEY = %s\n", r.Count, strings.ToLower(r.KeyHex))
		if r.IVHex != "" {
			fmt.Fprintf(&b, "IV = %s\n", strings.ToLower(r.IVHex))
		}
		if r.Plaintext != "" {
			fmt.Fprintf(&b, "PLAINTEXT = %s\n", strings.ToLower(r.Plaintext))
		}
		fmt.Fprintf(&b, "\nCIPHERTEXT = %s\n\n", strings.ToLower(r.Ciphertext))
	}
	return b.String()
}
