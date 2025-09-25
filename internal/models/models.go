package models

import "time"

type Role struct {
	ID   int    `gorm:"primaryKey;autoIncrement" json:"id"`
	Name string `gorm:"uniqueIndex;not null" json:"name"`
}
type User struct {
	ID           string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	Email        string    `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash string    `gorm:"not null" json:"-"`
	IsActive     bool      `gorm:"not null;default:true" json:"is_active"`
	Roles        []Role    `gorm:"many2many:user_roles" json:"roles"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
type Client struct {
	ID             string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	CompanyName    string    `gorm:"not null" json:"company_name"`
	ProductName    string    `gorm:"not null;default:UNKNOWN;size:30" json:"product_name"`
	ProductVersion string    `gorm:"not null;default:0.0;size:5"  json:"product_version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
type AuditLog struct {
	ID        int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    *string   `gorm:"type:uuid" json:"user_id,omitempty"`
	ClientID  *string   `gorm:"type:uuid" json:"client_id,omitempty"`
	Action    string    `gorm:"not null" json:"action"`
	Metadata  JSONB     `gorm:"type:jsonb;default:'{}'::jsonb" json:"metadata"`
	CreatedAt time.Time `json:"created_at"`
}
type Session struct {
	JTI       string     `gorm:"primaryKey;size:64" json:"jti"`
	UserID    string     `gorm:"type:uuid;index;not null" json:"user_id"`
	ExpiresAt time.Time  `gorm:"not null" json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}
