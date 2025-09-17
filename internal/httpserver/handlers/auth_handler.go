package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"testvec-backend/internal/auth"
	"testvec-backend/internal/models"
)

type registerReq struct {
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Roles    []string `json:"roles,omitempty"` // optional; default ["User"]
}

func Register(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req registerReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if req.Email == "" || req.Password == "" {
			http.Error(w, "email and password required", http.StatusBadRequest)
			return
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil { http.Error(w, "hash error", http.StatusInternalServerError); return }

		u := models.User{Email: req.Email, PasswordHash: hash, IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}

		// attach roles
		var roles []models.Role
		if len(req.Roles) == 0 {
			req.Roles = []string{"User"}
		}
		if err := db.Where("name IN ?", req.Roles).Find(&roles).Error; err == nil && len(roles) > 0 {
			u.Roles = roles
		}

		if err := db.Create(&u).Error; err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		respondJSON(w, map[string]any{"id": u.ID, "email": u.Email, "roles": req.Roles})
	}
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func Login(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req loginReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var u models.User
		if err := db.Preload("Roles").First(&u, "email = ?", strings.ToLower(req.Email)).Error; err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if err := auth.CheckPassword(u.PasswordHash, req.Password); err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		var roleNames []string
		for _, r := range u.Roles { roleNames = append(roleNames, r.Name) }
		tok, err := auth.Sign(u.ID, roleNames)
		if err != nil { http.Error(w, "token error", http.StatusInternalServerError); return }
		respondJSON(w, map[string]any{"token": tok})
	}
}

func Me(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub := auth.Subject(r.Context())
		var u models.User
		if err := db.Preload("Roles").First(&u, "id = ?", sub).Error; err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		respondJSON(w, map[string]any{
			"id": u.ID, "email": u.Email, "roles": u.Roles, "is_active": u.IsActive,
		})
	}
}
