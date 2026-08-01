package handler

import (
	"backend/internal/database/sqlc"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// UserHandler holds dependencies needed by user endpoints.
type UserHandler struct {
	DB      *pgxpool.Pool
	Queries *sqlc.Queries
}

// NewUserHandler is the constructor called by router.NewRouter.
func NewUserHandler(pool *pgxpool.Pool) *UserHandler {
	queries := sqlc.New(pool)
	return &UserHandler{DB: pool, Queries: queries}
}

// UserProfileResponse defines the JSON structure returned to clients.
type UserProfileResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (h *UserHandler) SignInDefault(w http.ResponseWriter, r *http.Request) {

	// 3. Return JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("")
}
