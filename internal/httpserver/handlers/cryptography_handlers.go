package handlers

import (
    "net/http"
    "trustcore/internal/models"

    "go.uber.org/zap"
    "gorm.io/gorm"
)

// GET /v1/cryptography
func ListCryptography(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var rows []models.Cryptography
        if err := db.Order("category, algorithm").Find(&rows).Error; err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        respondJSON(w, map[string]any{"data": rows, "count": len(rows)})
    }
}
