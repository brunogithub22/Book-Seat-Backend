package service

import (
	"backend/internal/security"
	"log/slog"
)

func HashPassword(argonHasher *security.ArgonHasher, password string) (string, error) {
	hashedPassword, err := argonHasher.HashPassword(password)
	if err != nil {
		slog.Error("Failed to hash password", "error", err.Error())
	}
	return hashedPassword, err
}
