# TrustCore Backend (1-day JWT + sessions)

- JWT access tokens valid **24 hours** (`exp = now + 24h`) and persisted **sessions** (table `sessions`) with same expiry.
- REST API: chi
- ORM: GORM + PostgreSQL
- Roles: Administrator (full) & User
- Default admin: `admin@trustcore.local` / `1234` (bcrypt-hashed on first boot)
- Client table (UUID, `company_name` NOT NULL) + CRUD
- Change-password endpoint
- Vector generation scaffold (KAT/MMT/MCT) and AES-CBC validator that parses NIST-style files.

Run:
```
cp .env.example .env
# set DATABASE_URL and JWT_SECRET
go mod tidy
go run ./cmd/api
```
