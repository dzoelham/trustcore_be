package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"testvec-backend/internal/httpserver"
	"testvec-backend/internal/logger"
	"testvec-backend/internal/models"
)

func main() {
	_ = godotenv.Load() // dev convenience

	lg := logger.New() // *zap.SugaredLogger
	defer lg.Sync()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		lg.Fatalw("DATABASE_URL is empty")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		lg.Fatalw("db connect failed", "error", err)
	}

	// AutoMigrate for early development; prefer SQL migrations in production.
	if err := db.AutoMigrate(&models.User{}, &models.Role{}, &models.Vector{}, &models.Verification{}, &models.AuditLog{}); err != nil {
		lg.Fatalw("automigrate failed", "error", err)
	}

	router := httpserver.NewRouter(db, lg)

	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "8080"
	}
	lg.Infow("listening", "port", port)
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatal(err)
	}
}
