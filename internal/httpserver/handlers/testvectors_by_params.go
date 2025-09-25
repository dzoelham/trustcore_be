package handlers

import (
    "encoding/json"
    "fmt"
    "net/http"
    "strings"

    "trustcore/internal/models"
    "trustcore/internal/services/vector"

    "github.com/google/uuid"
    "go.uber.org/zap"
    "gorm.io/gorm"
)

func sp(s string) *string { return &s }

// POST /v1/cryptography/vectors
func GenerateVectorsByParams(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
    type reqT struct {
        Algorithm       string `json:"algorithm"`
        Mode            string `json:"mode"`
        TestMode        string `json:"test_mode"`
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

        if alg == "" || mode == "" || tmode == "" {
            http.Error(w, "algorithm, mode, test_mode are required", http.StatusBadRequest)
            return
        }

        var exists bool
        if err := db.Model(&models.Client{}).
            Select("count(*) > 0").
            Where("id = ?", req.ClientID).
            Find(&exists).Error; err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        if !exists {
            http.Error(w, "client_id does not exist", http.StatusUnprocessableEntity)
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

            if err := db.Transaction(func(tx *gorm.DB) error {
                for _, e := range vec.Encrypt {
                    in := strings.ToLower(e.Plaintext)
                    out := strings.ToLower(e.Ciphertext)
                    row := models.Vector{
                        UserID:    req.UserID,
                        ClientID:  req.ClientID,
                        Algorithm: vec.Algorithm,
                        Mode:      vec.Mode,
                        TestMode:  vec.TestMode,
                        Direction: "ENCRYPT",
                        InputHex:  sp(in),
                        OutputHex: sp(out),
                        Status:    "ready",
                    }
                    if err := tx.Create(&row).Error; err != nil { return err }
                }
                for _, d := range vec.Decrypt {
                    in := strings.ToLower(d.Ciphertext)
                    out := strings.ToLower(d.Plaintext)
                    row := models.Vector{
                        UserID:    req.UserID,
                        ClientID:  req.ClientID,
                        Algorithm: vec.Algorithm,
                        Mode:      vec.Mode,
                        TestMode:  vec.TestMode,
                        Direction: "DECRYPT",
                        InputHex:  sp(in),
                        OutputHex: sp(out),
                        Status:    "ready",
                    }
                    if err := tx.Create(&row).Error; err != nil { return err }
                }
                return nil
            }); err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
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
