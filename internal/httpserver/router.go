package httpserver

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"testvec-backend/internal/auth"
	"testvec-backend/internal/httpserver/handlers"
)

func NewRouter(db *gorm.DB, lg *zap.SugaredLogger) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Recoverer)
	r.Use(middleware.Logger)

	// Public
	r.Post("/v1/auth/register", handlers.Register(db, lg))
	r.Post("/v1/auth/login", handlers.Login(db, lg))

	// Authenticated routes
	r.Group(func(protected chi.Router) {
		protected.Use(auth.JWTAuth())
		protected.Get("/v1/me", handlers.Me(db, lg))

		// Admin only
		protected.Group(func(admin chi.Router) {
			admin.Use(auth.RequireRole("Administrator"))
			admin.Get("/v1/users", handlers.ListUsers(db, lg))
			admin.Post("/v1/users", handlers.CreateUser(db, lg))
			admin.Patch("/v1/users/{id}", handlers.UpdateUser(db, lg))
			admin.Delete("/v1/users/{id}", handlers.DeleteUser(db, lg))
			admin.Post("/v1/users/{id}/roles", handlers.AssignRole(db, lg))
		})

		protected.Post("/v1/vectors/generate", handlers.GenerateVector(db, lg))
		protected.Post("/v1/vectors/verify", handlers.VerifyVector(db, lg))
		protected.Get("/v1/logs", handlers.MyLogs(db, lg))
	})

	// health
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	return r
}
