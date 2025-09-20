package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"trustcore/internal/auth"
	"trustcore/internal/models"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type GenReq struct {
	Algorithm, Method string
	Params            json.RawMessage
}

func GenerateVector(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := chi.URLParam(r, "client_id")
		uid := auth.Subject(r.Context())
		var req GenReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Algorithm == "" || req.Method == "" {
			http.Error(w, "algorithm and method are required", http.StatusBadRequest)
			return
		}
		inputHex := ""
		outputHex := ""
		v := models.Vector{ClientID: clientID, UserID: uid, Algorithm: strings.ToUpper(req.Algorithm), Method: strings.ToUpper(req.Method), Params: models.JSONB(req.Params), InputHex: &inputHex, OutputHex: &outputHex, Status: "ready", CreatedAt: time.Now()}
		if err := db.Create(&v).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		md, _ := json.Marshal(map[string]any{"vector_id": v.ID, "algorithm": v.Algorithm, "method": v.Method})
		_ = db.Create(&models.AuditLog{UserID: &uid, ClientID: &clientID, Action: "VECTOR_GENERATE", Metadata: models.JSONB(md)}).Error
		respondJSON(w, map[string]any{"vector_id": v.ID, "input_hex": inputHex, "output_hex": outputHex})
	}
}
