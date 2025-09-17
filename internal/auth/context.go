package auth

import (
	"context"
)

type ctxKey string

const (
	userKey   ctxKey = "userClaims"
)

type Claims struct {
	Subject string
	Roles   []string
}

func (c Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role { return true }
	}
	return false
}

func WithClaims(ctx context.Context, c Claims) context.Context {
	return context.WithValue(ctx, userKey, c)
}

func FromContext(ctx context.Context) Claims {
	if v, ok := ctx.Value(userKey).(Claims); ok {
		return v
	}
	return Claims{}
}

func Subject(ctx context.Context) string {
	return FromContext(ctx).Subject
}
