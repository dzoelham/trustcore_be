package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"trustcore/internal/auth"
	"trustcore/internal/httpserver"
	"trustcore/internal/logger"
	"trustcore/internal/models"

	"github.com/joho/godotenv"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

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
	if err := db.AutoMigrate(&models.Role{}, &models.User{}, &models.Client{}, &models.Vector{}, &models.AuditLog{}, &models.Session{}); err != nil {
		lg.Fatalw("automigrate failed", "error", err)
	}
	seedDefaultAdmin(db, lg)
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
