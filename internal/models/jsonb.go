package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSONB is a thin helper for storing arbitrary JSON with GORM.
type JSONB []byte

func (j JSONB) Value() (driver.Value, error) {
	if len(j) == 0 {
		return []byte("{}"), nil
	}
	return []byte(j), nil
}

func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = JSONB("{}")
		return nil
	}
	switch v := value.(type) {
	case []byte:
		*j = JSONB(v); return nil
	case string:
		*j = JSONB([]byte(v)); return nil
	default:
		b, err := json.Marshal(v)
		if err != nil { return fmt.Errorf("jsonb scan: %w", err) }
		*j = JSONB(b); return nil
	}
}
