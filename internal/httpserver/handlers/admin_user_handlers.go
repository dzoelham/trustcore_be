package handlers

import (
	"encoding/json"
	"net/http"
	"time"
	"trustcore/internal/auth"
	"trustcore/internal/models"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func ListUsers(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var users []models.User
		_ = db.Preload("Roles").Order("created_at desc").Find(&users).Error
		respondJSON(w, users)
	}
}
func CreateUser(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email, Password string
			Roles           []string
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Email == "" || req.Password == "" {
			http.Error(w, "email/password required", http.StatusBadRequest)
			return
		}
		hash, _ := auth.HashPassword(req.Password)
		u := models.User{Email: req.Email, PasswordHash: hash, IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
		var roles []models.Role
		if len(req.Roles) > 0 {
			_ = db.Where("name IN ?", req.Roles).Find(&roles).Error
		}
		u.Roles = roles
		if err := db.Create(&u).Error; err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		respondJSON(w, map[string]any{"id": u.ID})
	}
}
func UpdateUser(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var req struct {
			Email    *string
			IsActive *bool
			Password *string
			Roles    []string
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var u models.User
		if err := db.Preload("Roles").First(&u, "id = ?", id).Error; err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if req.Email != nil {
			u.Email = *req.Email
		}
		if req.IsActive != nil {
			u.IsActive = *req.IsActive
		}
		if req.Password != nil && *req.Password != "" {
			hash, _ := auth.HashPassword(*req.Password)
			u.PasswordHash = hash
		}
		if req.Roles != nil {
			var roles []models.Role
			_ = db.Where("name IN ?", req.Roles).Find(&roles).Error
			_ = db.Model(&u).Association("Roles").Replace(roles)
		}
		u.UpdatedAt = time.Now()
		if err := db.Save(&u).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, map[string]any{"updated": true})
	}
}
func DeleteUser(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if err := db.Delete(&models.User{}, "id = ?", id).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, map[string]any{"deleted": true})
	}
}
