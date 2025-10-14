package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"trustcore/internal/models"
	"trustcore/internal/services/vector"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func sp(s string) *string { return &s }

func containsFold(ss []string, v string) bool {
	v = strings.ToUpper(strings.TrimSpace(v))
	for _, s := range ss {
		if strings.ToUpper(strings.TrimSpace(s)) == v {
			return true
		}
	}
	return false
}

func containsInt(list []int, x int) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

// minimal struct so different vector types can be normalized and reused
type ioRow struct {
	Count      int
	KeyHex     string
	IVHex      string
	Plaintext  string
	Ciphertext string
}

// builds the TXT body for both ENCRYPT/DECRYPT sections reusing one code path
func buildTXT(enc, dec []ioRow, includeExpected bool) string {
	var b strings.Builder // efficient loop concatenation
	// ENCRYPT
	b.WriteString("[ENCRYPT]\n\n")
	for _, r := range enc {
		b.WriteString(fmt.Sprintf("COUNT = %d\n", r.Count))
		b.WriteString("KEY = " + strings.ToLower(r.KeyHex) + "\n")
		if strings.TrimSpace(r.IVHex) != "" {
			b.WriteString("IV = " + strings.ToLower(r.IVHex) + "\n")
		}
		b.WriteString("PLAINTEXT = " + strings.ToLower(r.Plaintext) + "\n")
		if includeExpected && strings.TrimSpace(r.Ciphertext) != "" {
			b.WriteString("CIPHERTEXT = " + strings.ToLower(r.Ciphertext) + "\n")
		}
		b.WriteString("\n")
	}

	// DECRYPT
	b.WriteString("[DECRYPT]\n\n")
	for _, r := range dec {
		b.WriteString(fmt.Sprintf("COUNT = %d\n", r.Count))
		b.WriteString("KEY = " + strings.ToLower(r.KeyHex) + "\n")
		if strings.TrimSpace(r.IVHex) != "" {
			b.WriteString("IV = " + strings.ToLower(r.IVHex) + "\n")
		}
		b.WriteString("CIPHERTEXT = " + strings.ToLower(r.Ciphertext) + "\n")
		if includeExpected && strings.TrimSpace(r.Plaintext) != "" {
			b.WriteString("PLAINTEXT = " + strings.ToLower(r.Plaintext) + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// persists ENCRYPT & DECRYPT rows in one place (transaction kept at call site)
func persistVectors(tx *gorm.DB, reqUserID, reqClientID, algorithm, mode, testMode string, enc, dec []ioRow) error {
	// ENCRYPT
	for _, e := range enc {
		in := strings.ToLower(e.Plaintext)
		out := strings.ToLower(e.Ciphertext)
		row := models.Vector{
			UserID:    reqUserID,
			ClientID:  reqClientID,
			Algorithm: algorithm,
			Mode:      mode,
			TestMode:  testMode,
			Direction: "ENCRYPT",
			InputHex:  sp(in),
			OutputHex: sp(out),
			Status:    "ready",
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
	}
	// DECRYPT
	for _, d := range dec {
		in := strings.ToLower(d.Ciphertext)
		out := strings.ToLower(d.Plaintext)
		row := models.Vector{
			UserID:    reqUserID,
			ClientID:  reqClientID,
			Algorithm: algorithm,
			Mode:      mode,
			TestMode:  testMode,
			Direction: "DECRYPT",
			InputHex:  sp(in),
			OutputHex: sp(out),
			Status:    "ready",
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
	}
	return nil
}

// POST /v1/cryptography/vectors
func GenerateVectorsByParams(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	type reqT struct {
		Algorithm string `json:"algorithm"`
		Mode      string `json:"mode"`
		TestMode  string `json:"test_mode"`

		// When AES + KAT, this selects the KAT "input mode"/subtype: gfsbox | keysbox | varkey | vartxt
		InputMode       string `json:"input_mode"`
		KeyBits         int    `json:"key_bits"`
		Count           int    `json:"count"`
		IncludeExpected bool   `json:"include_expected"`
		Format          string `json:"format"`
		UserID          string `json:"user_id"`
		ClientID        string `json:"client_id"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req reqT
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// UUID validations
		if err := uuid.Validate(req.UserID); err != nil {
			http.Error(w, "user_id must be a valid UUID", http.StatusBadRequest)
			return
		}
		if err := uuid.Validate(req.ClientID); err != nil {
			http.Error(w, "client_id must be a valid UUID", http.StatusBadRequest)
			return
		}

		alg := strings.ToUpper(strings.TrimSpace(req.Algorithm))
		mode := strings.ToUpper(strings.TrimSpace(req.Mode))
		tmode := strings.ToUpper(strings.TrimSpace(req.TestMode))

		// Extra validation: if AES + KAT, ensure input_mode is present and valid
		if strings.EqualFold(alg, "AES") && strings.EqualFold(tmode, "KAT") {
			allowed := []string{"GFSBOX", "KEYSBOX", "VARKEY", "VARTXT"}
			if strings.TrimSpace(strings.ToUpper(req.InputMode)) == "" {
				http.Error(w, fmt.Sprintf("for AES KAT, input_mode must be one of %v", allowed), http.StatusBadRequest)
				return
			}
			valid := false
			for _, a := range allowed {
				if strings.EqualFold(req.InputMode, a) {
					valid = true
					break
				}
			}
			if !valid {
				http.Error(w, fmt.Sprintf("for AES KAT, input_mode must be one of %v", allowed), http.StatusBadRequest)
				return
			}
		}

		if alg == "" || tmode == "" {
			http.Error(w, "algorithm and test_mode are required", http.StatusBadRequest)
			return
		}

		// Client & User existence
		var exists bool
		if err := db.Model(&models.Client{}).
			Select("count(*) > 0").Where("id = ?", req.ClientID).Find(&exists).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "client_id does not exist", http.StatusUnprocessableEntity)
			return
		}

		if err := db.Model(&models.User{}).
			Select("count(*) > 0").Where("id = ?", req.UserID).Find(&exists).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "user_id does not exist", http.StatusUnprocessableEntity)
			return
		}

		// Lookup cryptography catalogue and validate combination
		var cat models.Cryptography
		if err := db.Where("upper(algorithm) = ?", alg).First(&cat).Error; err != nil {
			http.Error(w, "algorithm not found in catalogue", http.StatusBadRequest)
			return
		}

		// Unmarshal JSONB fields
		var modes []string
		var testModes []string
		var keyLens []int

		if b, err := json.Marshal(cat.Modes); err == nil {
			_ = json.Unmarshal(b, &modes)
		}
		if b, err := json.Marshal(cat.TestModes); err == nil {
			_ = json.Unmarshal(b, &testModes)
		}
		if b, err := json.Marshal(cat.KeyLengths); err == nil {
			_ = json.Unmarshal(b, &keyLens)
		}

		// Helper: for all algorithm modes (fallback if catalogue is missing/empty)
		aesModes := []string{"ECB", "CBC", "CFB", "OFB", "CTR", "GCM"}
		tdeaModes := []string{"ECB", "CBC", "CFB", "OFB", "CTR"}
		camModes := []string{"ECB", "CBC", "CFB", "OFB", "CTR", "GCM"}

		// Decide how to validate `mode`
		category := strings.ToUpper(strings.TrimSpace(cat.Category))
		switch category {
		case "HASH", "MESSAGE AUTHENTICATION", "RANDOM NUMBER GENERATOR", "ASYMMETRIC TECHNIQUE", "KEY MANAGEMENT", "POST QUANTUM CRYPTOGRAPHY":
			// Mode-less families
			if strings.TrimSpace(mode) != "" {
				http.Error(w, fmt.Sprintf("%s does not use modes; omit 'mode'", cat.Algorithm), http.StatusBadRequest)
				return
			}
		default:
			// Things that may use modes (block ciphers; some stream ciphers)
			if len(modes) > 0 {
				if !containsFold(modes, mode) {
					sort.Strings(modes)
					http.Error(w, fmt.Sprintf("invalid mode for %s. allowed: %v", cat.Algorithm, modes), http.StatusBadRequest)
					return
				}
			} else {
				// Catalogue has empty/NULL modes; apply sensible fallback
				if strings.EqualFold(alg, "AES") {
					if !containsFold(aesModes, mode) {
						http.Error(w, fmt.Sprintf("invalid mode for AES. allowed: %v", aesModes), http.StatusBadRequest)
						return
					}
				} else if strings.EqualFold(alg, "TDEA") || strings.EqualFold(alg, "3DES") {
					if !containsFold(tdeaModes, mode) {
						http.Error(w, fmt.Sprintf("invalid mode for TDEA. allowed: %v", tdeaModes), http.StatusBadRequest)
						return
					}
				} else if strings.EqualFold(alg, "CAMELLIA") {
					if !containsFold(camModes, mode) {
						http.Error(w, fmt.Sprintf("invalid mode for Camellia. allowed: %v", camModes), http.StatusBadRequest)
						return
					}
				} else if strings.TrimSpace(mode) != "" && strings.EqualFold(category, "STREAM CIPHER") {
					// Stream ciphers typically have no modes -> require omit
					http.Error(w, fmt.Sprintf("%s is a stream cipher and does not use modes; omit 'mode'", cat.Algorithm), http.StatusBadRequest)
					return
				}
				// else: accept as-is (no strict mode validation available)
			}
		}

		// Validate test_mode and key_bits if catalogue provides them
		if len(testModes) > 0 && !containsFold(testModes, tmode) {
			http.Error(w, fmt.Sprintf("invalid test_mode for %s. allowed: %v", cat.Algorithm, testModes), http.StatusBadRequest)
			return
		}
		// key_bits validation fallback if table empty
		if len(keyLens) == 0 {
			if strings.EqualFold(alg, "AES") {
				keyLens = []int{128, 192, 256}
			}
			if strings.EqualFold(alg, "TDEA") || strings.EqualFold(alg, "3DES") {
				keyLens = []int{112, 168}
			}
		}
		if len(keyLens) > 0 && !containsInt(keyLens, req.KeyBits) {
			http.Error(w, fmt.Sprintf("invalid key_bits for %s. allowed: %v", cat.Algorithm, keyLens), http.StatusBadRequest)
			return
		}

		// Dispatch (now the branches are tiny and DRY)
		switch alg {
		case "AES":
			vec, err := vector.GenerateAESTestVectors(mode, tmode, vector.AESGenParams{
				KeyBits:         req.KeyBits,
				Count:           req.Count,
				IncludeExpected: req.IncludeExpected,
				KatVariant:      req.InputMode,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Normalize for reuse
			enc := make([]ioRow, 0, len(vec.Encrypt))
			for _, r := range vec.Encrypt {
				enc = append(enc, ioRow{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
			}
			dec := make([]ioRow, 0, len(vec.Decrypt))
			for _, r := range vec.Decrypt {
				dec = append(dec, ioRow{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
			}

			// Persist once using shared helper
			if err := db.Transaction(func(tx *gorm.DB) error {
				return persistVectors(tx, req.UserID, req.ClientID, vec.Algorithm, vec.Mode, vec.TestMode, enc, dec)
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if strings.ToLower(req.Format) == "txt" {
				txt := buildTXT(enc, dec, req.IncludeExpected)
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Disposition",
					fmt.Sprintf("attachment; filename=aes_%s_%s_%d.txt",
						strings.ToLower(vec.Mode), strings.ToLower(vec.TestMode), req.KeyBits))
				_, _ = w.Write([]byte(txt))
				return
			}

			respondJSON(w, vec)
			return

		case "TDEA", "3DES":
			vec, err := vector.GenerateTDEATestVectors(mode, tmode, vector.TDEAGenParams{
				KeyBits:         req.KeyBits,
				Count:           req.Count,
				IncludeExpected: req.IncludeExpected,
				KatVariant:      req.InputMode,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			enc := make([]ioRow, 0, len(vec.Encrypt))
			for _, r := range vec.Encrypt {
				enc = append(enc, ioRow{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
			}
			dec := make([]ioRow, 0, len(vec.Decrypt))
			for _, r := range vec.Decrypt {
				dec = append(dec, ioRow{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
			}

			if err := db.Transaction(func(tx *gorm.DB) error {
				return persistVectors(tx, req.UserID, req.ClientID, vec.Algorithm, vec.Mode, vec.TestMode, enc, dec)
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if strings.ToLower(req.Format) == "txt" {
				txt := buildTXT(enc, dec, req.IncludeExpected)
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Disposition",
					fmt.Sprintf("attachment; filename=tdea_%s_%s_%d.txt",
						strings.ToLower(vec.Mode), strings.ToLower(vec.TestMode), req.KeyBits))
				_, _ = w.Write([]byte(txt))
				return
			}

			respondJSON(w, vec)
			return

		case "CAMELLIA":
			vec, err := vector.GenerateCamelliaTestVectors(mode, tmode, vector.CamGenParams{
				KeyBits:         req.KeyBits,
				Count:           req.Count,
				IncludeExpected: req.IncludeExpected,
				KatVariant:      req.InputMode,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			enc := make([]ioRow, 0, len(vec.Encrypt))
			for _, r := range vec.Encrypt {
				enc = append(enc, ioRow{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
			}
			dec := make([]ioRow, 0, len(vec.Decrypt))
			for _, r := range vec.Decrypt {
				dec = append(dec, ioRow{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
			}

			if err := db.Transaction(func(tx *gorm.DB) error {
				return persistVectors(tx, req.UserID, req.ClientID, vec.Algorithm, vec.Mode, vec.TestMode, enc, dec)
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if strings.ToLower(req.Format) == "txt" {
				txt := buildTXT(enc, dec, req.IncludeExpected)
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Disposition",
					fmt.Sprintf("attachment; filename=camellia_%s_%s_%d.txt",
						strings.ToLower(vec.Mode), strings.ToLower(vec.TestMode), req.KeyBits))
				_, _ = w.Write([]byte(txt))
				return
			}

			respondJSON(w, vec)
			return

		default:
			http.Error(w, "algorithm/mode not implemented yet", http.StatusNotImplemented)
			return
		}
	}
}
