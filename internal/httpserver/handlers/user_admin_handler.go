package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"testvec-backend/internal/auth"
	"testvec-backend/internal/models"
)

func ListUsers(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var users []models.User
		if err := db.Preload("Roles").Order("created_at desc").Find(&users).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError); return
		}
		respondJSON(w, users)
	}
}

func CreateUser(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string   `json:"email"`
			Password string   `json:"password"`
			Roles    []string `json:"roles"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest); return
		}
		if req.Email == "" || req.Password == "" {
			http.Error(w, "email/password required", http.StatusBadRequest); return
		}
		hash, _ := auth.HashPassword(req.Password)
		u := models.User{Email: req.Email, PasswordHash: hash, IsActive: true}
		if len(req.Roles) > 0 {
			var roles []models.Role
			_ = db.Where("name IN ?", req.Roles).Find(&roles).Error
			u.Roles = roles
		}
		if err := db.Create(&u).Error; err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
		respondJSON(w, map[string]any{"id": u.ID})
	}
}

func UpdateUser(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var req struct {
			Email    *string `json:"email"`
			IsActive *bool   `json:"is_active"`
			Password *string `json:"password,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest); return
		}
		var u models.User
		if err := db.First(&u, "id = ?", id).Error; err != nil {
			http.Error(w, "not found", http.StatusNotFound); return
		}
		if req.Email != nil { u.Email = *req.Email }
		if req.IsActive != nil { u.IsActive = *req.IsActive }
		if req.Password != nil && *req.Password != "" {
			hash, _ := auth.HashPassword(*req.Password)
			u.PasswordHash = hash
		}
		if err := db.Save(&u).Error; err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
		respondJSON(w, map[string]any{"updated": true})
	}
}

func DeleteUser(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if err := db.Delete(&models.User{}, "id = ?", id).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError); return
		}
		respondJSON(w, map[string]any{"deleted": true})
	}
}

func AssignRole(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var body struct{ Roles []string `json:"roles"` }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest); return
		}
		var u models.User
		if err := db.Preload("Roles").First(&u, "id = ?", id).Error; err != nil {
			http.Error(w, "not found", http.StatusNotFound); return
		}
		var roles []models.Role
		if len(body.Roles) > 0 {
			if err := db.Where("name IN ?", body.Roles).Find(&roles).Error; err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest); return
			}
		}
		if err := db.Model(&u).Association("Roles").Replace(roles); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError); return
		}
		respondJSON(w, map[string]any{"ok": true})
	}
}
