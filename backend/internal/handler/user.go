package handler

import (
	"backend/internal/database/sqlc"
	"backend/internal/security"

	"net/http"

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

func (h *UserHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {

}
