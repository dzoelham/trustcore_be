// internal/db/migrate/seed_embed.go
package migrate

import "embed"

//go:embed 0005_seed_cryptography.up.sql
var SeedFS embed.FS
