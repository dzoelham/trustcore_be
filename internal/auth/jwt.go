package auth

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func parseTTL() time.Duration {
	if s := os.Getenv("JWT_EXPIRES_IN"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
	}
	return 24 * time.Hour
}

func Sign(userID string, roles []string) (string, error) {
	key := []byte(os.Getenv("JWT_SECRET"))
	claims := jwt.MapClaims{
		"sub":   userID,
		"roles": roles,
		"exp":   time.Now().Add(parseTTL()).Unix(),
		"iat":   time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

func Verify(tokenStr string) (Claims, error) {
	key := []byte(os.Getenv("JWT_SECRET"))
	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !tok.Valid {
		return Claims{}, errors.New("invalid token")
	}
	mapc, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return Claims{}, errors.New("invalid claims")
	}
	sub, _ := mapc["sub"].(string)
	var roles []string
	if arr, ok := mapc["roles"].([]interface{}); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok {
				roles = append(roles, s)
			}
		}
	}
	return Claims{Subject: sub, Roles: roles}, nil
}
