package service

import (
	"backend/internal/security"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/joho/godotenv"

	"github.com/google/uuid"
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

func GetRefreshToken(t *security.TokenService, r *http.Request) (string, error) {
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

func GetAccessToken(t *security.TokenService, r *http.Request) (string, error) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		// http.ErrNoCookie is the expected "not present" case — not an error worth logging
		if !errors.Is(err, http.ErrNoCookie) {
			slog.Warn("unexpected error reading access_token cookie", "error", err)
		}
		return "", err
	}
	if cookie.Value == "" {
		return "", err
	}
	return cookie.Value, err
}

func GetCSRFToken(t *security.TokenService, r *http.Request) (bool, error) {
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		// http.ErrNoCookie is the expected "not present" case — not an error worth logging
		if !errors.Is(err, http.ErrNoCookie) {
			slog.Warn("unexpected error reading refresh_token cookie", "error", err)
		}
		return false, err
	}
	if cookie.Value == "" {
		return false, err
	}
	return true, err
}

func ToPgUUID(id string) (pgtype.UUID, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgtype.UUID{Bytes: parsed, Valid: true}, nil
}

func Tokenkey() (*security.TokenService, error) {
	err := godotenv.Load()
	if err != nil {
		slog.Info("no .env file found, using system env vars")
	}
	jwtPWD := os.Getenv("PASSWORD_JWT")
	if jwtPWD == "" {
		return nil, err
	}
	var tokenService = security.NewTokenService(jwtPWD)
	return tokenService, err
}
