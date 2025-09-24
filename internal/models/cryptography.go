package models

import "time"

type Cryptography struct {
    ID            string    `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
    Algorithm     string    `gorm:"uniqueIndex;not null" json:"algorithm"`
    Category      string    `gorm:"not null" json:"category"`
    Modes         JSONB     `gorm:"type:jsonb;not null;default:'[]'::jsonb" json:"modes"`
    TestModes     JSONB     `gorm:"type:jsonb;not null;default:'[]'::jsonb" json:"test_modes"`
    KeyLengths    JSONB     `gorm:"type:jsonb;not null;default:'[]'::jsonb" json:"key_lengths"`
    BlockSizeBits *int      `json:"block_size_bits,omitempty"`
    IVSizeBits    *int      `json:"iv_size_bits,omitempty"`
    StandardRef   *string   `json:"standard_ref,omitempty"`
    Notes         *string   `json:"notes,omitempty"`
    CreatedAt     time.Time `json:"created_at"`
    UpdatedAt     time.Time `json:"updated_at"`
}
