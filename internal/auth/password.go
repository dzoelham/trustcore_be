package auth

import "golang.org/x/crypto/bcrypt"

// HashPassword hashes a plaintext password using bcrypt with DefaultCost.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

// CheckPassword compares a bcrypt hash with a candidate plaintext password.
func CheckPassword(hash, pw string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw))
}
