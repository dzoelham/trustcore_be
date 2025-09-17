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

type Vector struct {
	ID           string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	UserID       string    `gorm:"type:uuid;not null;index" json:"user_id"`
	Algorithm    string    `gorm:"not null" json:"algorithm"`
	Params       JSONB     `gorm:"type:jsonb;default:'{}'::jsonb" json:"params"`
	InputHex     *string   `json:"input_hex,omitempty"`
	InputPath    *string   `json:"input_path,omitempty"`
	ExpectedHex  string    `gorm:"not null" json:"expected_hex"`
	Status       string    `gorm:"not null;default:ready" json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

type Verification struct {
	ID             string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	UserID         string    `gorm:"type:uuid;not null;index" json:"user_id"`
	VectorID       *string   `gorm:"type:uuid" json:"vector_id,omitempty"`
	UploadedHex    *string   `json:"uploaded_hex,omitempty"`
	UploadedPath   *string   `json:"uploaded_path,omitempty"`
	IsMatch        *bool     `json:"is_match,omitempty"`
	MismatchReason *string   `json:"mismatch_reason,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type AuditLog struct {
	ID        int64   `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    *string `gorm:"type:uuid" json:"user_id,omitempty"`
	Action    string  `gorm:"not null" json:"action"`
	Metadata  JSONB   `gorm:"type:jsonb;default:'{}'::jsonb" json:"metadata"`
	CreatedAt time.Time `json:"created_at"`
}
