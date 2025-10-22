package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"trustcore/internal/auth"
	"trustcore/internal/db/migrate"
	"trustcore/internal/httpserver"
	"trustcore/internal/logger"
	"trustcore/internal/models"

	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func runCryptoSeed(db *gorm.DB) error {
	sqlBytes, err := migrate.SeedFS.ReadFile("0005_seed_cryptography.up.sql")
	if err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		return tx.Exec(string(sqlBytes)).Error
	})
}

func main() {
	_ = godotenv.Load()

	lg := logger.New()
	defer lg.Sync()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		lg.Fatalw("DATABASE_URL is empty")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		lg.Fatalw("db connect failed", "error", err)
	}

	if err := db.AutoMigrate(
		&models.Role{}, &models.User{}, &models.Client{},
		&models.Vector{}, &models.AuditLog{}, &models.Session{}, &models.Cryptography{},
	); err != nil {
		lg.Fatalw("automigrate failed", "error", err)
	}

	seedDefaultAdmin(db, lg)
	if err := runCryptoSeed(db); err != nil {
		lg.Fatalw("cryptography seed failed", "error", err)
	}

	// Build the HTTP router from your internal server
	router := httpserver.NewRouter(db, lg)

	// ---- CORS Configuration (Firefox-compatible) ----
	frontendOrigin := os.Getenv("FRONTEND_ORIGIN")
	if frontendOrigin == "" {
		frontendOrigin = "http://localhost:5173"
	}

	// Build allowlist for common localhost variants
	allowedOrigins := []string{
		frontendOrigin,
		"http://localhost:5173",
		"http://127.0.0.1:5173",
		"http://localhost:5174",
	}

	lg.Infow("CORS Configuration", "allowedOrigins", allowedOrigins)

	// More permissive CORS for Firefox compatibility
	c := cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			// Allow requests with no origin (like Postman, curl)
			if origin == "" {
				return true
			}
			for _, allowed := range allowedOrigins {
				if origin == allowed {
					lg.Infow("CORS ALLOWED", "origin", origin)
					return true
				}
			}
			lg.Warnw("CORS REJECTED", "origin", origin, "allowedOrigins", allowedOrigins)
			return false
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
			http.MethodHead,
		},
		// Be explicit about allowed headers for Firefox
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
			"X-Requested-With",
		},
		ExposedHeaders:   []string{"Content-Length", "Authorization"},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours - longer cache for Firefox
		Debug:            false, // Disable debug in production
	})

	// Enhanced logging middleware
	logMw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			origin := r.Header.Get("Origin")
			lg.Infow("REQUEST",
				"method", r.Method,
				"path", r.URL.Path,
				"origin", origin,
				"userAgent", r.Header.Get("User-Agent"),
			)
			next.ServeHTTP(w, r)
			lg.Infow("RESPONSE",
				"method", r.Method,
				"path", r.URL.Path,
				"duration", time.Since(start),
			)
		})
	}

	// Apply middleware: log -> CORS -> router
	handler := logMw(c.Handler(router))

	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "8080"
	}

	lg.Infow("Server starting",
		"port", port,
		"frontendOrigin", frontendOrigin,
		"allowedOrigins", allowedOrigins,
		"allowCredentials", true,
	)

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

func seedDefaultAdmin(db *gorm.DB, lg *zap.SugaredLogger) {
	db.Exec("INSERT INTO roles(name) VALUES ('Administrator') ON CONFLICT DO NOTHING")
	db.Exec("INSERT INTO roles(name) VALUES ('User') ON CONFLICT DO NOTHING")
	var count int64
	db.Model(&models.User{}).Where("LOWER(email)=?", "admin@trustcore.local").Count(&count)
	if count > 0 {
		return
	}
	hash, _ := auth.HashPassword("1234")
	u := models.User{Email: strings.ToLower("admin@trustcore.local"), PasswordHash: hash, IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.Create(&u).Error; err == nil {
		var adminRole models.Role
		if err := db.First(&adminRole, "name = 'Administrator'").Error; err == nil {
			_ = db.Model(&u).Association("Roles").Append(&adminRole)
		}
	}
	lg.Infow("seeded default admin", "email", "admin@trustcore.local")
}
