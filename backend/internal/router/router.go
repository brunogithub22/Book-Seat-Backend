package router

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"backend/internal/database/sqlc"
	"backend/internal/handler"
	"backend/internal/middleware"
	"backend/internal/security"
)

// NewRouter constructs and returns the primary application HTTP handler.
// It receives the database pool initialized in main.go and injects it into handlers.
func NewRouter(db *pgxpool.Pool, queries *sqlc.Queries) http.Handler {
	// 1. Create a new Go standard library multiplexer
	mux := http.NewServeMux()

	// 2. Initialize handlers with dependencies
	//userHandler := handler.NewUserHandler(db)
	authHandler := handler.NewAuthHandler(db, queries, security.NewArgonHasher(nil))

	// -----------------------------------------------------------------
	// PUBLIC ROUTES
	// -----------------------------------------------------------------
	mux.HandleFunc("POST /api/auth/signup", authHandler.SignUp)
	mux.HandleFunc("POST /api/auth/signin", authHandler.SignIn)
	mux.HandleFunc("POST /api/auth/me", authHandler.AuthMe)
	mux.HandleFunc("POST /api/auth/refresh", authHandler.Refresh)

	// OAuth 2.0 Auth Flow
	//mux.HandleFunc("GET /auth/google/login", authHandler.HandleGoogleLogin)
	//mux.HandleFunc("GET /auth/google/callback", authHandler.HandleGoogleCallback)

	// -----------------------------------------------------------------
	// PROTECTED ROUTES (Require JWT Authentication)
	// -----------------------------------------------------------------
	//mux.HandleFunc("GET /api/user/profile", middleware.JWTAuth(userHandler.GetProfile))

	// -----------------------------------------------------------------
	// GLOBAL MIDDLEWARE WRAPPERS
	// -----------------------------------------------------------------
	// Apply global middleware like logging and recovery across ALL routes
	var appHandler http.Handler = mux
	appHandler = middleware.Logger(appHandler)
	appHandler = middleware.Recoverer(appHandler)

	return appHandler
}
