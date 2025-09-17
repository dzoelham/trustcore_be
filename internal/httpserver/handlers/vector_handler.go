package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"testvec-backend/internal/auth"
	"testvec-backend/internal/models"
	"testvec-backend/internal/services/vector"
	"testvec-backend/internal/util"
)

type GenerateReq struct {
	Algorithm string          `json:"algorithm"`
	Params    json.RawMessage `json:"params"`
}
type GenerateRes struct {
	VectorID    string `json:"vector_id"`
	InputHex    string `json:"input_hex,omitempty"`
	ExpectedHex string `json:"expected_hex"`
}

func GenerateVector(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req GenerateReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest); return
		}

		var inputHex, outputHex string
		var paramsJSON []byte
		switch strings.ToUpper(req.Algorithm) {
		case "SHA256":
			var p vector.SHA256Params
			_ = json.Unmarshal(req.Params, &p)
			var err error
			inputHex, outputHex, err = vector.GenerateSHA256(p)
			if err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
			paramsJSON, _ = json.Marshal(p)
		case "AES-CTR":
			var p vector.AESCTRParams
			_ = json.Unmarshal(req.Params, &p)
			inHex, outHex, pOut, err := vector.GenerateAESCTR(p)
			if err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
			inputHex, outputHex = inHex, outHex
			paramsJSON, _ = json.Marshal(pOut)
		case "HMAC-SHA256":
			var p vector.HMACSHA256Params
			_ = json.Unmarshal(req.Params, &p)
			inHex, outHex, pOut, err := vector.GenerateHMACSHA256(p)
			if err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
			inputHex, outputHex = inHex, outHex
			paramsJSON, _ = json.Marshal(pOut)
		default:
			http.Error(w, "unsupported algorithm", http.StatusBadRequest); return
		}

		v := models.Vector{
			UserID:      auth.Subject(r.Context()),
			Algorithm:   req.Algorithm,
			Params:      models.JSONB(paramsJSON),
			InputHex:    &inputHex,
			ExpectedHex: outputHex,
			Status:      "ready",
		}
		if err := db.Create(&v).Error; err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }

		_ = db.Create(&models.AuditLog{
			UserID: &v.UserID, Action: "VECTOR_GENERATE",
			Metadata: models.JSONB([]byte(`{"vector_id":"`+v.ID+`","algorithm":"`+v.Algorithm+`"}`)),
		})

		respondJSON(w, GenerateRes{VectorID: v.ID, InputHex: inputHex, ExpectedHex: outputHex})
	}
}

func VerifyVector(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var uploadedHex string
		vectorID := r.URL.Query().Get("vector_id")

		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			_ = r.ParseMultipartForm(16 << 20)
			f, _, err := r.FormFile("file")
			if err != nil { http.Error(w, "file required", http.StatusBadRequest); return }
			defer f.Close()
			b, _ := io.ReadAll(f)
			if util.IsLikelyHex(string(b)) {
				uploadedHex = strings.TrimSpace(string(b))
			} else {
				uploadedHex = hex.EncodeToString(b)
			}
		} else {
			var body struct{ VectorID, UploadedHex string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.VectorID != "" { vectorID = body.VectorID }
			uploadedHex = body.UploadedHex
		}

		var v models.Vector
		if vectorID != "" {
			if err := db.First(&v, "id = ?", vectorID).Error; err != nil {
				http.Error(w, "vector not found", http.StatusNotFound); return
			}
		}

		var expected string
		if v.ID != "" {
			expected = v.ExpectedHex
		} else {
			in, err := hex.DecodeString(uploadedHex)
			if err != nil { http.Error(w, "invalid hex", http.StatusBadRequest); return }
			out := sha256.Sum256(in)
			expected = hex.EncodeToString(out[:])
		}

		match := strings.EqualFold(uploadedHex, expected)
		ver := models.Verification{
			UserID:     auth.Subject(r.Context()),
			UploadedHex: &uploadedHex,
			IsMatch:    &match,
		}
		if v.ID != "" { ver.VectorID = &v.ID }

		_ = db.Create(&ver).Error
		_ = db.Create(&models.AuditLog{
			UserID: &ver.UserID, Action: "VERIFY",
			Metadata: models.JSONB([]byte(`{"verification_id":"`+ver.ID+`","vector_id":"`+v.ID+`"}`)),
		})

		respondJSON(w, map[string]any{
			"verification_id": ver.ID, "vector_id": v.ID, "match": match, "expected_hex": expected,
		})
	}
}
