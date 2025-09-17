package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

type BlockVector struct {
	Plaintext   string `json:"plaintext"`
	Ciphertext  string `json:"ciphertext_true"`
	CiphertextG string `json:"ciphertext_computed"`
	OK          bool   `json:"ok"`
}

type TestVector struct {
	Name        string        `json:"name"`
	Algorithm   string        `json:"algorithm"`
	Mode        string        `json:"mode"`
	KeySizeBits int           `json:"key_size_bits"`
	Key         string        `json:"key"`
	IV          string        `json:"iv,omitempty"`           // CBC
	InitCounter string        `json:"init_counter,omitempty"` // CTR (full 128-bit initial counter block)
	Blocks      []BlockVector `json:"blocks"`
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		log.Fatalf("hex decode failed for %q: %v", s, err)
	}
	return b
}

// Simple ECB using cipher.Block
func aesECBEncrypt(b cipher.Block, pt []byte) []byte {
	if len(pt)%b.BlockSize() != 0 {
		log.Fatalf("ECB pt len must be multiple of block size: got %d", len(pt))
	}
	out := make([]byte, len(pt))
	for i := 0; i < len(pt); i += b.BlockSize() {
		b.Encrypt(out[i:i+b.BlockSize()], pt[i:i+b.BlockSize()])
	}
	return out
}

// CBC (no padding; vectors are block-aligned)
func aesCBCEncrypt(key, iv, pt []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	if len(pt)%block.BlockSize() != 0 {
		log.Fatalf("CBC pt len must be multiple of block size: got %d", len(pt))
	}
	out := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, pt)
	return out
}

// CTR (SP 800-38A CTR examples use a 128-bit initial counter block)
func aesCTREncrypt(key, initCtr, pt []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	out := make([]byte, len(pt))
	cipher.NewCTR(block, initCtr).XORKeyStream(out, pt)
	return out
}

func runECB(tv *TestVector) {
	key := mustHex(tv.Key)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	for i := range tv.Blocks {
		pt := mustHex(tv.Blocks[i].Plaintext)
		ctWant := mustHex(tv.Blocks[i].Ciphertext)
		ct := aesECBEncrypt(block, pt)
		tv.Blocks[i].CiphertextG = hex.EncodeToString(ct)
		tv.Blocks[i].OK = bytes.Equal(ct, ctWant)
	}
}

func runCBC(tv *TestVector) {
	key := mustHex(tv.Key)
	iv := mustHex(tv.IV)
	for i := range tv.Blocks {
		pt := mustHex(tv.Blocks[i].Plaintext)
		ctWant := mustHex(tv.Blocks[i].Ciphertext)
		ct := aesCBCEncrypt(key, iv, pt)
		tv.Blocks[i].CiphertextG = hex.EncodeToString(ct)
		tv.Blocks[i].OK = bytes.Equal(ct, ctWant)
		// CBC example vectors are per-block; we feed one block each time with same IV
		// so re-derive the IV as the previous CT for the next block:
		if i+1 < len(tv.Blocks) {
			iv = mustHex(tv.Blocks[i].Ciphertext)
		}
	}
}

func runCTR(tv *TestVector) {
	key := mustHex(tv.Key)
	ctr := mustHex(tv.InitCounter)
	for i := range tv.Blocks {
		pt := mustHex(tv.Blocks[i].Plaintext)
		ctWant := mustHex(tv.Blocks[i].Ciphertext)
		// construct a stream starting at current counter value
		ct := aesCTREncrypt(key, ctr, pt)
		tv.Blocks[i].CiphertextG = hex.EncodeToString(ct)
		tv.Blocks[i].OK = bytes.Equal(ct, ctWant)
		// increment the 128-bit counter for next block (big-endian, per 38A)
		incrementBigEndian(ctr)
	}
}

func incrementBigEndian(buf []byte) {
	for i := len(buf) - 1; i >= 0; i-- {
		buf[i]++
		if buf[i] != 0 {
			break
		}
	}
}

func main() {
	var vectors []TestVector

	// ---------- ECB-AES128 (SP 800-38A F.1.1) ----------
	vectors = append(vectors, TestVector{
		Name:        "F.1.1 ECB-AES128.Encrypt",
		Algorithm:   "AES",
		Mode:        "ECB",
		KeySizeBits: 128,
		Key:         "2b7e151628aed2a6abf7158809cf4f3c",
		Blocks: []BlockVector{
			{Plaintext: "6bc1bee22e409f96e93d7e117393172a", Ciphertext: "3ad77bb40d7a3660a89ecaf32466ef97"},
			{Plaintext: "ae2d8a571e03ac9c9eb76fac45af8e51", Ciphertext: "f5d3d58503b9699de785895a96fdbaaf"},
			{Plaintext: "30c81c46a35ce411e5fbc1191a0a52ef", Ciphertext: "43b1cd7f598ece23881b00e3ed030688"},
			{Plaintext: "f69f2445df4f9b17ad2b417be66c3710", Ciphertext: "7b0c785e27e8ad3f8223207104725dd4"},
		},
	})

	// ---------- ECB-AES192 (SP 800-38A F.1.3) ----------
	vectors = append(vectors, TestVector{
		Name:        "F.1.3 ECB-AES192.Encrypt",
		Algorithm:   "AES",
		Mode:        "ECB",
		KeySizeBits: 192,
		Key:         "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
		Blocks: []BlockVector{
			{Plaintext: "6bc1bee22e409f96e93d7e117393172a", Ciphertext: "bd334f1d6e45f25ff712a214571fa5cc"},
			{Plaintext: "ae2d8a571e03ac9c9eb76fac45af8e51", Ciphertext: "974104846d0ad3ad7734ecb3ecee4eef"},
			{Plaintext: "30c81c46a35ce411e5fbc1191a0a52ef", Ciphertext: "ef7afd2270e2e60adce0ba2face6444e"},
			{Plaintext: "f69f2445df4f9b17ad2b417be66c3710", Ciphertext: "9a4b41ba738d6c72fb16691603c18e0e"},
		},
	})

	// ---------- ECB-AES256 (SP 800-38A F.1.5) ----------
	vectors = append(vectors, TestVector{
		Name:        "F.1.5 ECB-AES256.Encrypt",
		Algorithm:   "AES",
		Mode:        "ECB",
		KeySizeBits: 256,
		Key:         "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
		Blocks: []BlockVector{
			{Plaintext: "6bc1bee22e409f96e93d7e117393172a", Ciphertext: "f3eed1bdb5d2a03c064b5a7e3db181f8"},
			{Plaintext: "ae2d8a571e03ac9c9eb76fac45af8e51", Ciphertext: "591ccb10d410ed26dc5ba74a31362870"},
			{Plaintext: "30c81c46a35ce411e5fbc1191a0a52ef", Ciphertext: "b6ed21b99ca6f4f9f153e7b1beafed1d"},
			{Plaintext: "f69f2445df4f9b17ad2b417be66c3710", Ciphertext: "23304b7a39f9f3ff067d8d8f9e24ecc7"},
		},
	})

	// ---------- CBC-AES128 (SP 800-38A F.2.1) ----------
	vectors = append(vectors, TestVector{
		Name:        "F.2.1 CBC-AES128.Encrypt",
		Algorithm:   "AES",
		Mode:        "CBC",
		KeySizeBits: 128,
		Key:         "2b7e151628aed2a6abf7158809cf4f3c",
		IV:          "000102030405060708090a0b0c0d0e0f",
		Blocks: []BlockVector{
			{Plaintext: "6bc1bee22e409f96e93d7e117393172a", Ciphertext: "7649abac8119b246cee98e9b12e9197d"},
			{Plaintext: "ae2d8a571e03ac9c9eb76fac45af8e51", Ciphertext: "5086cb9b507219ee95db113a917678b2"},
			{Plaintext: "30c81c46a35ce411e5fbc1191a0a52ef", Ciphertext: "73bed6b8e3c1743b7116e69e22229516"},
			{Plaintext: "f69f2445df4f9b17ad2b417be66c3710", Ciphertext: "3ff1caa1681fac09120eca307586e1a7"},
		},
	})

	// ---------- CTR-AES128 (SP 800-38A F.5.1) ----------
	vectors = append(vectors, TestVector{
		Name:        "F.5.1 CTR-AES128.Encrypt",
		Algorithm:   "AES",
		Mode:        "CTR",
		KeySizeBits: 128,
		Key:         "2b7e151628aed2a6abf7158809cf4f3c",
		InitCounter: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		Blocks: []BlockVector{
			{Plaintext: "6bc1bee22e409f96e93d7e117393172a", Ciphertext: "874d6191b620e3261bef6864990db6ce"},
			{Plaintext: "ae2d8a571e03ac9c9eb76fac45af8e51", Ciphertext: "9806f66b7970fdff8617187bb9fffdff"},
			{Plaintext: "30c81c46a35ce411e5fbc1191a0a52ef", Ciphertext: "5ae4df3edbd5d35e5b4f09020db03eab"},
			{Plaintext: "f69f2445df4f9b17ad2b417be66c3710", Ciphertext: "1e031dda2fbe03d1792170a0f3009cee"},
		},
	})

	// Compute & verify each vector
	for i := range vectors {
		switch vectors[i].Mode {
		case "ECB":
			runECB(&vectors[i])
		case "CBC":
			runCBC(&vectors[i])
		case "CTR":
			runCTR(&vectors[i])
		default:
			log.Fatalf("unknown mode: %s", vectors[i].Mode)
		}
	}

	// Pretty-print JSON
	out, _ := json.MarshalIndent(vectors, "", "  ")
	fmt.Println(string(out))
}
