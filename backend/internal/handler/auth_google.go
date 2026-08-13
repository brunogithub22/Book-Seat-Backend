package handler

import (
	"backend/internal/database/sqlc"
	"backend/internal/security"
	"backend/internal/service"
	"encoding/json"
	"net/http"

	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sqlc-dev/pqtype"
)

type AuthGoogleHandler struct {
	DB          *pgxpool.Pool
	Queries     *sqlc.Queries
	ArgonHasher *security.ArgonHasher
}

// GoogleClaims holds the identity fields we actually need out of the id_token.
// Google's id_token carries many more claims than this (aud, iss, iat, exp,
// email_verified, picture, locale...) — only pull out what FindOrCreateByGoogleSub needs.
type GoogleClaims struct {
	Sub           string // stable, unique Google user ID — this is the FK you store, not email
	Email         string
	EmailVerified bool
	FirstName     string
	Surname       string
}

// verifyGoogleIDToken validates the id_token's signature against Google's public
// keys (fetched and cached internally by the idtoken package) and checks that the
// token's audience matches our own GOOGLE_CLIENT_ID — this is what stops someone
// from handing us a valid Google id_token that was actually issued for a
// *different* application.
func verifyGoogleIDToken(ctx context.Context, rawIDToken string) (*GoogleClaims, error) {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")

	payload, err := idtoken.Validate(ctx, rawIDToken, clientID)
	if err != nil {
		return nil, err // signature invalid, expired, or aud mismatch — caller logs and rejects
	}

	sub, ok := payload.Claims["sub"].(string)
	if !ok || sub == "" {
		return nil, errors.New("id_token missing sub claim")
	}

	email, _ := payload.Claims["email"].(string) // absent if "email" scope wasn't granted
	emailVerified, _ := payload.Claims["email_verified"].(bool)
	givenName, _ := payload.Claims["given_name"].(string)
	familyName, _ := payload.Claims["family_name"].(string)

	if email == "" {
		slog.Warn("google id_token has no email claim", "sub", sub)
	}

	return &GoogleClaims{
		Sub:           sub,
		Email:         email,
		EmailVerified: emailVerified,
		FirstName:     givenName,
		Surname:       familyName,
	}, nil
}

var googleOAuthConfig *oauth2.Config

// call this once from main(), after godotenv.Load()
func InitGoogleOAuthConfig() {
	googleOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Scopes: []string{
			"openid",
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// NewAuthHandler is the constructor called by router.NewRouter.
func NewAuthGoogleHandler(pool *pgxpool.Pool, queries *sqlc.Queries, argonHasher *security.ArgonHasher) *AuthGoogleHandler {
	return &AuthGoogleHandler{DB: pool, Queries: queries, ArgonHasher: argonHasher}
}

func (h *AuthGoogleHandler) Login(w http.ResponseWriter, r *http.Request) {

	slog.Info("Login STARTED")

	state, err := generateState()
	if err != nil {
		slog.Error("failed to generate oauth state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/api/auth/google", // covers this route + the callback below
		HttpOnly: true,
		Secure:   false, // same field you already thread through NewRouter
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 min, plenty for the round trip
	})

	url := googleOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	slog.Info("Login STOPPED")
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *AuthGoogleHandler) Callback(w http.ResponseWriter, r *http.Request) {

	var userID pgtype.UUID

	clientIP := security.GetClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	slog.Info("Callback STARTED")
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
		return
	}

	tokenService, err := service.Tokenkey()
	if err != nil {
		http.Error(w, "JWTPassword error", http.StatusInternalServerError)
		slog.Error("JWT Error")
		return
	}

	queryState := r.URL.Query().Get("state")
	if queryState == "" || queryState != stateCookie.Value {
		slog.Error("oauth state mismatch", "error", errors.New("possible CSRF"))
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	// state cookie is single-use — clear it now
	http.SetCookie(w, &http.Cookie{
		Name: "oauth_state", Value: "", Path: "/api/auth/google",
		HttpOnly: true, Secure: false, SameSite: http.SameSiteLaxMode,
		MaxAge: -1,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	token, err := googleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		slog.Error("google token exchange failed", "error", err)
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		slog.Error("no id_token in google response", "error", errors.New("missing id_token"))
		http.Error(w, "authentication failed", http.StatusBadGateway)
		return
	}

	claims, err := verifyGoogleIDToken(ctx, rawIDToken) // wraps google.golang.org/api/idtoken
	if err != nil {
		slog.Error("id_token verification failed", "error", err)
		http.Error(w, "invalid identity token", http.StatusUnauthorized)
		return
	}

	slog.Info("Email", ":", claims.Email)

	// --- Step 2: find-or-create, inside a transaction ---
	tx, err := h.DB.Begin(r.Context())
	if err != nil {
		slog.Error("failed to begin transaction", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())
	qtx := h.Queries.WithTx(tx)

	user, err := qtx.GetUserByEmail(r.Context(), claims.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info("No existing account found for", "email", claims.Email)
		} else {
			slog.Error("email verification failed", "error", err)
			http.Error(w, "invalid email verification", http.StatusUnauthorized)
			return
		}
	}
	not_exists := errors.Is(err, pgx.ErrNoRows)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info("No existing account found for", "email", user.Email)
		} else {
			slog.Error("Something went wrong during the check of the account")
			return
		}
	}
	if not_exists {
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

		newUser, err := qtx.CreatePerson(r.Context(), sqlc.CreatePersonParams{
			UserRole: pqtype.NullRawMessage{
				RawMessage: roleJSON,
				Valid:      true, // Tells the driver this value is not NULL
			},
			UserName:      claims.FirstName,
			Surname:       claims.Surname,
			PasswordHash:  "",
			Email:         claims.Email,
			Remember:      true,
			GoogleAccount: true,
		})
		if err != nil {
			http.Error(w, "Error creating the account", http.StatusInternalServerError)
			slog.Error("Error during creation of the account")
		}
		userID = newUser.ID
		slog.Info("Account addedd", "name", newUser.Email)
	} else {
		userID = user.ID
		slog.Info("Account was previulsy addedd")
	}

	// 1. Create the JWT access token
	accessToken, err := tokenService.GenerateAccessToken(userID.String(), claims.Email)
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
	if err := qtx.InsertRefreshToken(r.Context(), sqlc.InsertRefreshTokenParams{
		UserID:    userID,
		TokenHash: refreshHash,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(security.RefreshTokenTTL), Valid: true},
		UserAgent: pgtype.Text{String: userAgent, Valid: userAgent != ""},
		IpAddress: pgtype.Text{String: clientIP, Valid: clientIP != ""},
		IsRevoked: false,
		CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}); err != nil {
		slog.Error("failed to store refresh token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("failed to commit transaction", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 4. Send both raw tokens to the browser as HttpOnly cookies
	security.SetAuthCookies(w, accessToken, refreshToken)
	slog.Info("Auth cookies set for user", "email", claims.Email, "id", userID)

	slog.Info("Callback STOPPED")

	http.Redirect(w, r, os.Getenv("FRONTEND_URL")+"/dashboard", http.StatusFound)
}
