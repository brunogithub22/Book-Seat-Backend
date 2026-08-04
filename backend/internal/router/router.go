package router

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"backend/internal/handler"
	"backend/internal/middleware"
)

// NewRouter constructs and returns the primary application HTTP handler.
// It receives the database pool initialized in main.go and injects it into handlers.
func NewRouter(db *pgxpool.Pool) http.Handler {
	// 1. Create a new Go standard library multiplexer
	mux := http.NewServeMux()

	// 2. Initialize handlers with dependencies
	userHandler := handler.NewUserHandler(db)
	//authHandler := handler.NewAuthHandler(db)

	// -----------------------------------------------------------------
	// PUBLIC ROUTES
	// -----------------------------------------------------------------
	mux.HandleFunc("POST /api/auth/signup", userHandler.SignUp)
	mux.HandleFunc("POST /api/auth/signin", userHandler.SignIn)

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
