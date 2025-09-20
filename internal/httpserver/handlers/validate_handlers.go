package handlers

import (
	"encoding/json"
	"net/http"
	"trustcore/internal/auth"
	"trustcore/internal/models"
	"trustcore/internal/services/vector"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func ValidateAESCBC(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := auth.Subject(r.Context())
		clientID := chi.URLParam(r, "client_id")
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			http.Error(w, "multipart parse error", http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", http.StatusBadRequest)
			return
		}
		defer file.Close()
		recs, err := vector.ParseAESCBCVectorFile(file)
		if err != nil {
			http.Error(w, "parse error: "+err.Error(), http.StatusBadRequest)
			return
		}
		result, err := vector.ValidateAESCBC(recs)
		if err != nil {
			http.Error(w, "validate error: "+err.Error(), http.StatusBadRequest)
			return
		}
		md, _ := json.Marshal(map[string]any{"algorithm": "AES-CBC", "result": result})
		_ = db.Create(&models.AuditLog{UserID: &uid, ClientID: &clientID, Action: "VALIDATE_AES_CBC", Metadata: models.JSONB(md)}).Error
		respondJSON(w, result)
	}
}
