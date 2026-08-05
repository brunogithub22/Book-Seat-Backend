package handler

import (
	"backend/internal/database/sqlc"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"backend/internal/security"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserHandler holds dependencies needed by user endpoints.
type UserHandler struct {
	DB          *pgxpool.Pool
	Queries     *sqlc.Queries
	ArgonHasher *security.ArgonHasher
}

// NewUserHandler is the constructor called by router.NewRouter.
func NewUserHandler(pool *pgxpool.Pool, queries *sqlc.Queries, argonHasher *security.ArgonHasher) *UserHandler {
	return &UserHandler{DB: pool, Queries: queries, ArgonHasher: argonHasher}
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

func (h *UserHandler) SignUp(w http.ResponseWriter, r *http.Request) {

	var payload SignupPayload

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
		hashedPassword, err := h.ArgonHasher.HashPassword(payload.Password)
		if err != nil {
			slog.Error("Failed to hash password", "error", err.Error())
			http.Error(w, `{"message":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		slog.Info("Creating new account for", "email", payload.Email, "hashedPassword", hashedPassword)

	}

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
