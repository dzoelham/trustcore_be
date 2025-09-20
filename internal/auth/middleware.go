package auth

import (
	"net/http"
	"strings"
	"time"
	"trustcore/internal/models"

	"gorm.io/gorm"
)

func JWTAuth(db *gorm.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			raw := strings.TrimPrefix(h, "Bearer ")
			claims, err := Verify(raw)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			var sess models.Session
			if claims.JWTID == "" || db.First(&sess, "jti = ?", claims.JWTID).Error != nil {
				http.Error(w, "session not found", http.StatusUnauthorized)
				return
			}
			if sess.RevokedAt != nil || time.Now().After(sess.ExpiresAt) {
				http.Error(w, "session expired/revoked", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}

func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !FromContext(r.Context()).HasRole(role) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
