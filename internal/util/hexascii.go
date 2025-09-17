package util

import (
	"encoding/hex"
	"strings"
)

func IsLikelyHex(s string) bool {
	s = strings.TrimSpace(strings.ReplaceAll(s, " ", ""))
	if len(s)%2 != 0 { return false }
	_, err := hex.DecodeString(s)
	return err == nil
}

func ToHex(s string) (string, error) {
	s = strings.TrimSpace(s)
	if IsLikelyHex(s) {
		return strings.ToLower(strings.ReplaceAll(s, " ", "")), nil
	}
	return hex.EncodeToString([]byte(s)), nil
}
