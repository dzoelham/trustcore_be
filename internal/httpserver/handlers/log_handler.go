package handlers

import (
	"net/http"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"testvec-backend/internal/auth"
	"testvec-backend/internal/models"
)

// MyLogs returns recent audit logs. Regular users see their own logs.
// Administrators can pass ?all=1 to see recent logs for everyone.
func MyLogs(db *gorm.DB, lg *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all := r.URL.Query().Get("all") == "1"
		var logs []models.AuditLog
		if all && auth.FromContext(r.Context()).HasRole("Administrator") {
			_ = db.Order("created_at desc").Limit(200).Find(&logs).Error
		} else {
			uid := auth.Subject(r.Context())
			_ = db.Where("user_id = ?", uid).Order("created_at desc").Limit(200).Find(&logs).Error
		}
		respondJSON(w, logs)
	}
}
