package handlers

import (
	"encoding/json"
	"net/http"
	"time"
	"trustcore/internal/models"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func CreateClient(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CompanyName string `json:"company_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.CompanyName == "" {
			http.Error(w, "company_name required", http.StatusBadRequest)
			return
		}
		c := models.Client{CompanyName: req.CompanyName, CreatedAt: time.Now(), UpdatedAt: time.Now()}
		if err := db.Create(&c).Error; err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		respondJSON(w, c)
	}
}
func ListClients(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cs []models.Client
		_ = db.Order("created_at desc").Find(&cs).Error
		respondJSON(w, cs)
	}
}
func UpdateClient(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var req struct {
			CompanyName *string `json:"company_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var c models.Client
		if err := db.First(&c, "id = ?", id).Error; err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if req.CompanyName != nil {
			c.CompanyName = *req.CompanyName
		}
		c.UpdatedAt = time.Now()
		if err := db.Save(&c).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, map[string]any{"updated": true})
	}
}
func DeleteClient(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if err := db.Delete(&models.Client{}, "id = ?", id).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, map[string]any{"deleted": true})
	}
}
