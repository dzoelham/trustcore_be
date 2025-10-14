package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"trustcore/internal/models"
	"trustcore/internal/services/vector"
)

type reqT struct {
	Algorithm       string `json:"algorithm"`
	Mode            string `json:"mode"`
	TestMode        string `json:"test_mode"`
	InputMode       string `json:"input_mode"` // KAT variant (GFSBOX/KEYSBOX/VARKEY/VARTXT)
	KeyBits         int    `json:"key_bits"`
	Count           int    `json:"count"`
	IncludeExpected bool   `json:"include_expected"`
	Format          string `json:"format"` // "txt" => download; otherwise JSON
	UserID          string `json:"user_id"`
	ClientID        string `json:"client_id"`
}

// unified row for TXT + DB
type row struct {
	Count      int    `json:"count"`
	KeyHex     string `json:"key"`
	IVHex      string `json:"iv"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

type stdVec struct {
	Algorithm string
	Mode      string
	TestMode  string
	Enc       []row
	Dec       []row
}

// --- tiny utilities ---

func up(s string) string  { return strings.ToUpper(strings.TrimSpace(s)) }
func low(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func strptr(s string) *string {
	v := s
	return &v
}
func hasFold(list []string, v string) bool {
	v = up(v)
	for _, s := range list {
		if up(s) == v {
			return true
		}
	}
	return false
}
func hasInt(list []int, x int) bool {
	return slices.Contains(list, x)
}

// TXT writer (ENCRYPT/DECRYPT) using strings.Builder (idiomatic & efficient)
func buildTXT(enc, dec []row, includeExpected bool) string {
	var b strings.Builder
	b.WriteString("[ENCRYPT]\n\n")
	for _, r := range enc {
		b.WriteString(fmt.Sprintf("COUNT = %d\n", r.Count))
		b.WriteString("KEY = " + low(r.KeyHex) + "\n")
		if strings.TrimSpace(r.IVHex) != "" {
			b.WriteString("IV = " + low(r.IVHex) + "\n")
		}
		b.WriteString("PLAINTEXT = " + low(r.Plaintext) + "\n")
		if includeExpected && r.Ciphertext != "" {
			b.WriteString("CIPHERTEXT = " + low(r.Ciphertext) + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("[DECRYPT]\n\n")
	for _, r := range dec {
		b.WriteString(fmt.Sprintf("COUNT = %d\n", r.Count))
		b.WriteString("KEY = " + low(r.KeyHex) + "\n")
		if strings.TrimSpace(r.IVHex) != "" {
			b.WriteString("IV = " + low(r.IVHex) + "\n")
		}
		b.WriteString("CIPHERTEXT = " + low(r.Ciphertext) + "\n")
		if includeExpected && r.Plaintext != "" {
			b.WriteString("PLAINTEXT = " + low(r.Plaintext) + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// persist both directions in batches
func persistVectors(tx *gorm.DB, req reqT, v stdVec) error {
	enc := make([]models.Vector, 0, len(v.Enc))
	for _, e := range v.Enc {
		enc = append(enc, models.Vector{
			UserID:    req.UserID,
			ClientID:  req.ClientID,
			Algorithm: v.Algorithm,
			Mode:      v.Mode,
			TestMode:  v.TestMode,
			Direction: "ENCRYPT",
			InputHex:  strptr(low(e.Plaintext)),
			OutputHex: strptr(low(e.Ciphertext)),
			Status:    "ready",
		})
	}
	dec := make([]models.Vector, 0, len(v.Dec))
	for _, d := range v.Dec {
		dec = append(dec, models.Vector{
			UserID:    req.UserID,
			ClientID:  req.ClientID,
			Algorithm: v.Algorithm,
			Mode:      v.Mode,
			TestMode:  v.TestMode,
			Direction: "DECRYPT",
			InputHex:  strptr(low(d.Ciphertext)),
			OutputHex: strptr(low(d.Plaintext)),
			Status:    "ready",
		})
	}
	if len(enc) > 0 {
		if err := tx.Create(&enc).Error; err != nil { // GORM batch insert
			return err
		}
	}
	if len(dec) > 0 {
		if err := tx.Create(&dec).Error; err != nil {
			return err
		}
	}
	return nil
}

// --- generator adapters → stdVec ---

type baseParams struct {
	KeyBits         int
	Count           int
	IncludeExpected bool
	KatVariant      string
}

func aesGen(mode, tmode string, p baseParams) (stdVec, error) {
	vec, err := vector.GenerateAESTestVectors(mode, tmode, vector.AESGenParams{
		KeyBits:         p.KeyBits,
		Count:           p.Count,
		IncludeExpected: p.IncludeExpected,
		KatVariant:      p.KatVariant,
	})
	if err != nil {
		return stdVec{}, err
	}
	out := stdVec{Algorithm: vec.Algorithm, Mode: vec.Mode, TestMode: vec.TestMode}
	for _, r := range vec.Encrypt {
		out.Enc = append(out.Enc, row{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
	}
	for _, r := range vec.Decrypt {
		out.Dec = append(out.Dec, row{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
	}
	return out, nil
}

func tdeaGen(mode, tmode string, p baseParams) (stdVec, error) {
	vec, err := vector.GenerateTDEATestVectors(mode, tmode, vector.TDEAGenParams{
		KeyBits:         p.KeyBits,
		Count:           p.Count,
		IncludeExpected: p.IncludeExpected,
		KatVariant:      p.KatVariant,
	})
	if err != nil {
		return stdVec{}, err
	}
	out := stdVec{Algorithm: vec.Algorithm, Mode: vec.Mode, TestMode: vec.TestMode}
	for _, r := range vec.Encrypt {
		out.Enc = append(out.Enc, row{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
	}
	for _, r := range vec.Decrypt {
		out.Dec = append(out.Dec, row{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
	}
	return out, nil
}

func camGen(mode, tmode string, p baseParams) (stdVec, error) {
	vec, err := vector.GenerateCamelliaTestVectors(mode, tmode, vector.CamGenParams{
		KeyBits:         p.KeyBits,
		Count:           p.Count,
		IncludeExpected: p.IncludeExpected,
		KatVariant:      p.KatVariant,
	})
	if err != nil {
		return stdVec{}, err
	}
	out := stdVec{Algorithm: vec.Algorithm, Mode: vec.Mode, TestMode: vec.TestMode}
	for _, r := range vec.Encrypt {
		out.Enc = append(out.Enc, row{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
	}
	for _, r := range vec.Decrypt {
		out.Dec = append(out.Dec, row{r.Count, r.KeyHex, r.IVHex, r.Plaintext, r.Ciphertext})
	}
	return out, nil
}

// gens is assigned in init() so we can safely set aliases without init cycles
var gens map[string]func(mode, tmode string, p baseParams) (stdVec, error)

func init() {
	gens = map[string]func(mode, tmode string, p baseParams) (stdVec, error){
		"AES":      aesGen,
		"TDEA":     tdeaGen,
		"CAMELLIA": camGen,
	}
	// alias AFTER map exists → no self-reference during initialization
	gens["3DES"] = gens["TDEA"]
}

// --- catalogue & request validation ---

func validateUserAndClient(db *gorm.DB, userID, clientID string) error {
	if err := uuid.Validate(userID); err != nil {
		return fmt.Errorf("user_id must be a valid UUID")
	}
	if err := uuid.Validate(clientID); err != nil {
		return fmt.Errorf("client_id must be a valid UUID")
	}
	var exists bool
	if err := db.Model(&models.Client{}).
		Select("count(*) > 0").Where("id = ?", clientID).Find(&exists).Error; err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("client_id does not exist")
	}
	if err := db.Model(&models.User{}).
		Select("count(*) > 0").Where("id = ?", userID).Find(&exists).Error; err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("user_id does not exist")
	}
	return nil
}

func validateFromCatalogue(db *gorm.DB, req reqT) (allowedModes []string, allowedTests []string, allowedKeyBits []int, category string, err error) {
	var cat models.Cryptography
	if err = db.Where("upper(algorithm) = ?", up(req.Algorithm)).First(&cat).Error; err != nil {
		return nil, nil, nil, "", fmt.Errorf("algorithm not found in catalogue")
	}

	// jsonb → slices (handle json.Marshal’s two return values)
	if bm, e := json.Marshal(cat.Modes); e == nil && bm != nil {
		_ = json.Unmarshal(bm, &allowedModes)
	}
	if bt, e := json.Marshal(cat.TestModes); e == nil && bt != nil {
		_ = json.Unmarshal(bt, &allowedTests)
	}
	if bk, e := json.Marshal(cat.KeyLengths); e == nil && bk != nil {
		_ = json.Unmarshal(bk, &allowedKeyBits)
	}

	category = up(strings.TrimSpace(cat.Category))

	switch category {
	case "HASH", "MESSAGE AUTHENTICATION", "RANDOM NUMBER GENERATOR", "ASYMMETRIC TECHNIQUE", "KEY MANAGEMENT", "POST QUANTUM CRYPTOGRAPHY":
		// Mode-less families
		if strings.TrimSpace(req.Mode) != "" {
			return nil, nil, nil, category, fmt.Errorf("%s does not use modes; omit 'mode'", cat.Algorithm)
		}
	default:
		if len(allowedModes) > 0 && !hasFold(allowedModes, req.Mode) {
			sort.Strings(allowedModes)
			return nil, nil, nil, category, fmt.Errorf("invalid mode for %s. allowed: %v", cat.Algorithm, allowedModes)
		}
	}

	if len(allowedTests) > 0 && !hasFold(allowedTests, req.TestMode) {
		return nil, nil, nil, category, fmt.Errorf("invalid test_mode for %s. allowed: %v", cat.Algorithm, allowedTests)
	}

	// sensible defaults if key lengths empty
	if len(allowedKeyBits) == 0 {
		switch up(req.Algorithm) {
		case "AES":
			allowedKeyBits = []int{128, 192, 256}
		case "TDEA", "3DES":
			allowedKeyBits = []int{112, 168}
		}
	}
	if len(allowedKeyBits) > 0 && !hasInt(allowedKeyBits, req.KeyBits) {
		return nil, nil, nil, category, fmt.Errorf("invalid key_bits for %s. allowed: %v", cat.Algorithm, allowedKeyBits)
	}
	return allowedModes, allowedTests, allowedKeyBits, category, nil
}

// --- HTTP handler ---

func GenerateVectorsByParams(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req reqT
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := validateUserAndClient(db, req.UserID, req.ClientID); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		if _, _, _, _, err := validateFromCatalogue(db, req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		gen, ok := gens[up(req.Algorithm)]
		if !ok {
			http.Error(w, "algorithm/mode not implemented yet", http.StatusNotImplemented)
			return
		}

		v, err := gen(up(req.Mode), up(req.TestMode), baseParams{
			KeyBits:         req.KeyBits,
			Count:           req.Count,
			IncludeExpected: req.IncludeExpected,
			KatVariant:      up(req.InputMode),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := db.Transaction(func(tx *gorm.DB) error {
			return persistVectors(tx, req, v)
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if strings.EqualFold(req.Format, "txt") {
			txt := buildTXT(v.Enc, v.Dec, req.IncludeExpected)
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Disposition",
				fmt.Sprintf("attachment; filename=%s_%s_%s_%d.txt",
					low(v.Algorithm), low(v.Mode), low(v.TestMode), req.KeyBits))
			_, _ = w.Write([]byte(txt))
			return
		}

		type resp struct {
			Algorithm string `json:"algorithm"`
			Mode      string `json:"mode"`
			TestMode  string `json:"test_mode"`
			Encrypt   []row  `json:"encrypt"`
			Decrypt   []row  `json:"decrypt"`
		}
		respondJSON(w, resp{
			Algorithm: v.Algorithm,
			Mode:      v.Mode,
			TestMode:  v.TestMode,
			Encrypt:   v.Enc,
			Decrypt:   v.Dec,
		})
	}
}
