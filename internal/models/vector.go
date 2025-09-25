package models

import "time"

// JSONB is assumed to be defined elsewhere in your project (e.g., models/jsonb.go),
// as referenced by other models like Cryptography.
// If it's not present, define a JSONB type that implements scanner/valuer.

type Vector struct {
    ID        string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
    UserID    string    `gorm:"type:uuid;not null" json:"user_id"`
    ClientID  string    `gorm:"type:uuid;not null" json:"client_id"`
    Algorithm string    `gorm:"not null" json:"algorithm"`

    // Fields used by different generators/handlers
    Method    string    `json:"method"`                   // e.g., "CBC", "GCM" or generic "method"
    Mode      string    `json:"mode"`                     // when applicable (AES/CBC etc.)
    TestMode  string    `json:"test_mode"`                // KAT/MMT/MCT when applicable
    Direction string    `json:"direction"`                // ENCRYPT or DECRYPT

    Params    JSONB     `gorm:"type:jsonb" json:"params"` // arbitrary parameters

    // Hex payloads (pointers to satisfy existing handler expecting *string)
    InputHex  *string   `json:"input_hex"`
    OutputHex *string   `json:"output_hex"`

    Status    string    `json:"status"`                   // ready, done, failed, etc.
    CreatedAt time.Time `json:"created_at"`
}

func (Vector) TableName() string { return "vectors" }
