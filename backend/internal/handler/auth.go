package handler

import (
	"backend/internal/database/sqlc"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/sqlc-dev/pqtype"

	"backend/internal/security"
	"backend/internal/service"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserHandler holds dependencies needed by user endpoints.
type AuthHandler struct {
	DB          *pgxpool.Pool
	Queries     *sqlc.Queries
	ArgonHasher *security.ArgonHasher
}

// NewAuthHandler is the constructor called by router.NewRouter.
func NewAuthHandler(pool *pgxpool.Pool, queries *sqlc.Queries, argonHasher *security.ArgonHasher) *AuthHandler {
	return &AuthHandler{DB: pool, Queries: queries, ArgonHasher: argonHasher}
}

type SignupPayload struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type SigninPayload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type RoleData struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

func (h *AuthHandler) SignUp(w http.ResponseWriter, r *http.Request) {

	var payload SignupPayload
	var hashedPassword string
	var tokenService = security.NewTokenService("your-secret-key")

	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // rejects unexpected fields instead of silently ignoring them

	if err := decoder.Decode(&payload); err != nil {
		http.Error(w, `{"message":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if payload.Email == "" || payload.Password == "" {
		http.Error(w, `{"message":"email and password are required"}`, http.StatusBadRequest)
		return
	}

	user, err := h.Queries.GetUserByEmail(r.Context(), payload.Email)
	exists := errors.Is(err, pgx.ErrNoRows)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info("No existing account found for", "email", payload.Email)
		} else {
			slog.Error("Something went wrong during the check of the account")
		}
	} else {
		slog.Error("Account already exists for", "email", user.Email, "id", user.ID)
		http.Error(w, `{"message":"account already exists"}`, http.StatusConflict)
		return
	}

	if !exists {
		hashedPassword, err := service.HashPassword(h.ArgonHasher, payload.Password)
		if err != nil {
			slog.Error("Failed to hash password", "error", err.Error())
			http.Error(w, `{"message":"failed to hash password"}`, http.StatusInternalServerError)
			return
		}
		slog.Info("Successfully hashed password for", "email", payload.Email, "hashedPassword", hashedPassword)
	}

	roleObj := RoleData{
		Role:        "admin", // or payload.Role
		Permissions: []string{"read", "write", "delete"},
	}

	// 2. Marshal to []byte
	roleJSON, err := json.Marshal(roleObj)
	if err != nil {
		http.Error(w, `{"message":"invalid role format"}`, http.StatusBadRequest)
		return
	}

	newUser, err := h.Queries.CreatePerson(r.Context(), sqlc.CreatePersonParams{
		UserRole: pqtype.NullRawMessage{
			RawMessage: roleJSON,
			Valid:      true, // Tells the driver this value is not NULL
		},
		UserName:     payload.FirstName,
		Surname:      payload.LastName,
		PasswordHash: hashedPassword,
		Email:        payload.Email,
	})

	// 1. Create the JWT access token
	accessToken, err := tokenService.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		slog.Error("failed to generate access token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 2. Create the opaque refresh token (raw for client, hash for DB)
	refreshToken, refreshHash, err := security.GenerateRefreshToken()
	if err != nil {
		slog.Error("failed to generate refresh token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 3. Persist only the hash
	if err := h.Queries.InsertRefreshToken(r.Context(), sqlc.InsertRefreshTokenParams{
		UserID:    user.ID,
		TokenHash: refreshHash,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(security.RefreshTokenTTL), Valid: true},
	}); err != nil {
		slog.Error("failed to store refresh token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 4. Send both raw tokens to the browser as HttpOnly cookies
	security.SetAuthCookies(w, accessToken, refreshToken)

	slog.Info("New user created", "email", newUser.UserName, "id", newUser.ID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(
		UserInfo{
			ID:    "user-id",
			Email: payload.Email,
			Name:  "placeholder",
		},
	)
}

func (h *UserHandler) SignIn(w http.ResponseWriter, r *http.Request) {

	var payload SigninPayload

	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // rejects unexpected fields instead of silently ignoring them

	if err := decoder.Decode(&payload); err != nil {
		http.Error(w, `{"message":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if payload.Email == "" || payload.Password == "" {
		http.Error(w, `{"message":"email and password are required"}`, http.StatusBadRequest)
		return
	}

	slog.Info("user logged in", "email", payload.Email)

	// TODO: look up user, verify password hash (bcrypt.CompareHashAndPassword), issue token

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(
		UserInfo{
			ID:    "user-id",
			Email: payload.Email,
			Name:  "placeholder",
		},
	)
}
