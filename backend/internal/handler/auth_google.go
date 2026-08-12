package handler

import (
	"backend/internal/database/sqlc"
	"backend/internal/security"
	"net/http"

	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
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
	Name          string
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
	name, _ := payload.Claims["name"].(string)

	if email == "" {
		slog.Warn("google id_token has no email claim", "sub", sub)
	}

	return &GoogleClaims{
		Sub:           sub,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
	}, nil
}

var googleOAuthConfig = &oauth2.Config{
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
	RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"), // e.g. https://yourapp.com/api/auth/google/callback
	Scopes: []string{
		"openid",
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	},
	Endpoint: google.Endpoint,
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
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *AuthGoogleHandler) Callback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "missing state cookie", http.StatusBadRequest)
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

	slog.Info(claims.Email)

	http.Redirect(w, r, os.Getenv("FRONTEND_URL")+"/dashboard", http.StatusFound)
}
