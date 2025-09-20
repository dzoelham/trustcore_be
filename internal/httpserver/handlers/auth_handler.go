package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"trustcore/internal/auth"
	"trustcore/internal/models"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

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
		for _, r := range u.Roles {
			roleNames = append(roleNames, r.Name)
		}
		jtiB := make([]byte, 16)
		if _, err := rand.Read(jtiB); err != nil {
			http.Error(w, "jti error", http.StatusInternalServerError)
			return
		}
		jti := hex.EncodeToString(jtiB)
		_ = db.Create(&models.Session{JTI: jti, UserID: u.ID, ExpiresAt: time.Now().Add(24 * time.Hour), CreatedAt: time.Now()}).Error
		tok, err := auth.Sign(u.ID, roleNames, jti)
		if err != nil {
			http.Error(w, "token error", http.StatusInternalServerError)
			return
		}
		respondJSON(w, map[string]any{"token": tok})
	}
}

// POST /v1/auth/logout  (authenticated)
func Logout(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jti := auth.FromContext(r.Context()).JWTID
		if jti != "" {
			_ = db.Model(&models.Session{}).Where("jti = ?", jti).Update("revoked_at", time.Now()).Error
		}
		respondJSON(w, map[string]any{"ok": true})
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
		respondJSON(w, map[string]any{"id": u.ID, "email": u.Email, "roles": u.Roles, "is_active": u.IsActive})
	}
}

func ChangePassword(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ OldPassword, NewPassword string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(req.NewPassword) < 4 {
			http.Error(w, "new password too short", http.StatusBadRequest)
			return
		}
		uid := auth.Subject(r.Context())
		var u models.User
		if err := db.First(&u, "id = ?", uid).Error; err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err := auth.CheckPassword(u.PasswordHash, req.OldPassword); err != nil {
			http.Error(w, "invalid old password", http.StatusUnauthorized)
			return
		}
		hash, _ := auth.HashPassword(req.NewPassword)
		u.PasswordHash = hash
		u.UpdatedAt = time.Now()
		if err := db.Save(&u).Error; err != nil {
			http.Error(w, "save error", http.StatusInternalServerError)
			return
		}
		respondJSON(w, map[string]any{"changed": true})
	}
}
