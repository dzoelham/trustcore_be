package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"trustcore/internal/services/vector"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// POST /v1/cryptography/vectors
// Body:
//
//	{
//	  "algorithm": "AES",
//	  "mode": "CBC",
//	  "test_mode": "KAT"|"MMT"|"MCT",
//	  "key_bits": 128|192|256,
//	  "count": 10,
//	  "include_expected": true,
//	  "format": "json"|"txt"
//	}
func GenerateVectorsByParams(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	type reqT struct {
		Algorithm       string `json:"algorithm"`
		Mode            string `json:"mode"`
		TestMode        string `json:"test_mode"`
		KeyBits         int    `json:"key_bits"`
		Count           int    `json:"count"`
		IncludeExpected bool   `json:"include_expected"`
		Format          string `json:"format"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req reqT
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		alg := strings.ToUpper(strings.TrimSpace(req.Algorithm))
		mode := strings.ToUpper(strings.TrimSpace(req.Mode))
		tmode := strings.ToUpper(strings.TrimSpace(req.TestMode))

		if alg == "" || mode == "" || tmode == "" {
			http.Error(w, "algorithm, mode, test_mode are required", http.StatusBadRequest)
			return
		}

		if alg == "AES" && mode == "CBC" {
			tm := vector.AESCBCTestMode(tmode)
			vec, err := vector.GenerateAESCBCTestVectors(tm, vector.AESCBGParams{
				KeyBits:         req.KeyBits,
				Count:           req.Count,
				IncludeExpected: req.IncludeExpected,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if strings.ToLower(req.Format) == "txt" {
				txt := vec.ToTXT()
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=aes_cbc_%s_%d.txt", tmode, req.KeyBits))
				_, _ = w.Write([]byte(txt))
				return
			}
			respondJSON(w, vec)
			return
		}

		http.Error(w, "algorithm/mode not implemented yet", http.StatusNotImplemented)
	}
}
