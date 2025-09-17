# Test Vector Backend (Go 1.25.x)

A minimal, production-leaning REST backend for generating and verifying cryptographic test vectors.

## Quick start

1. Copy `.env.example` to `.env` and adjust values.
2. Start PostgreSQL and set `DATABASE_URL` accordingly.
3. (Dev only) Let GORM auto-migrate tables on first run.
4. `go run ./cmd/api`

## REST outline

- POST /v1/auth/register
- POST /v1/auth/login
- GET  /v1/me
- Admin (Administrator role required)
  - GET    /v1/users
  - POST   /v1/users
  - PATCH  /v1/users/{id}
  - DELETE /v1/users/{id}
  - POST   /v1/users/{id}/roles
- Vectors
  - POST /v1/vectors/generate   (SHA256, AES-CTR, HMAC-SHA256)
  - POST /v1/vectors/verify     (multipart file or JSON)
- Logs
  - GET  /v1/logs               (own logs; admin can use ?all=1)
