package service

import (
	"backend/internal/security"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgtype"
)

func HashPassword(argonHasher *security.ArgonHasher, password string) (string, error) {
	hashedPassword, err := argonHasher.HashPassword(password)
	if err != nil {
		slog.Error("Failed to hash password", "error", err.Error())
	}
	return hashedPassword, err
}

func VerifyPassword(argonHasher *security.ArgonHasher, payload_pwd string, db_pwd string) (bool, error) {
	equal, err := argonHasher.VerifyPassword(payload_pwd, db_pwd)
	if err != nil {
		slog.Error("Failed to verify password", "error", err.Error())
	}
	return equal, err
}

func GetRefreshToken(t *security.TokenService, r *http.Request, user_id pgtype.UUID) (string, error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		// http.ErrNoCookie is the expected "not present" case — not an error worth logging
		if !errors.Is(err, http.ErrNoCookie) {
			slog.Warn("unexpected error reading refresh_token cookie", "error", err)
		}
		return "", err
	}

	if cookie.Value == "" {
		return "", err
	}

	hash := security.HashToken(cookie.Value)

	return hash, err
}
