package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"trustcore/internal/models"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func CreateClient(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type createClientReq struct {
			CompanyName    string  `json:"company_name"`
			ProductName    *string `json:"product_name,omitempty"`
			ProductVersion *string `json:"product_version,omitempty"`
		}

		var req createClientReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		company := strings.TrimSpace(req.CompanyName)
		if company == "" {
			http.Error(w, "company_name required", http.StatusBadRequest)
			return
		}

		// Defaults per model tags when omitted or blank
		pname := "UNKNOWN"
		if req.ProductName != nil {
			pname = strings.TrimSpace(*req.ProductName)
			if pname == "" {
				pname = "UNKNOWN"
			}
		}

		pver := "0.0"
		if req.ProductVersion != nil {
			pver = strings.TrimSpace(*req.ProductVersion)
			if pver == "" {
				pver = "0.0"
			}
		}

		// Enforce length constraints (same as size:30 and size:5)
		if utf8.RuneCountInString(pname) > 30 {
			http.Error(w, "product_name must be <= 30 characters", http.StatusBadRequest)
			return
		}
		if utf8.RuneCountInString(pver) > 5 {
			http.Error(w, "product_version must be <= 5 characters", http.StatusBadRequest)
			return
		}

		c := models.Client{
			CompanyName:    company,
			ProductName:    pname,
			ProductVersion: pver,
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}

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
