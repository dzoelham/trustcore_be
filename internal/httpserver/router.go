package httpserver

import (
	"net/http"
	"trustcore/internal/auth"
	"trustcore/internal/httpserver/handlers"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func NewRouter(db *gorm.DB, lg *zap.SugaredLogger) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Recoverer, middleware.Logger)
	r.Post("/v1/auth/login", handlers.Login(db, lg))
	r.Group(func(protected chi.Router) {
		protected.Use(auth.JWTAuth(db))
		protected.Get("/v1/me", handlers.Me(db, lg))
		protected.Post("/v1/auth/logout", handlers.Logout(db))
		protected.Post("/v1/auth/password", handlers.ChangePassword(db, lg))
		protected.Group(func(admin chi.Router) {
			admin.Use(auth.RequireRole("Administrator"))
			admin.Get("/v1/admin/users", handlers.ListUsers(db, lg))
			admin.Post("/v1/admin/users", handlers.CreateUser(db, lg))
			admin.Patch("/v1/admin/users/{id}", handlers.UpdateUser(db, lg))
			admin.Delete("/v1/admin/users/{id}", handlers.DeleteUser(db, lg))
		})
		protected.Post("/v1/clients", handlers.CreateClient(db, lg))
		protected.Get("/v1/clients", handlers.ListClients(db, lg))
		protected.Patch("/v1/clients/{id}", handlers.UpdateClient(db, lg))
		protected.Delete("/v1/clients/{id}", handlers.DeleteClient(db, lg))
		protected.Post("/v1/clients/{client_id}/vectors/generate", handlers.GenerateVector(db, lg))
		protected.Post("/v1/clients/{client_id}/vectors/validate/aes-cbc", handlers.ValidateAESCBC(db, lg))
		protected.Get("/v1/logs", handlers.MyLogs(db, lg))
	})
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	return r
}
