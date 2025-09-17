package auth

import (
	"net/http"
	"strings"
)

// JWTAuth validates Authorization: Bearer <token> and populates context claims.
func JWTAuth() func(http.Handler) http.Handler {
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
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}

// RequireRole ensures the current user has the specified role.
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
