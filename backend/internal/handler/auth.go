package handler

import (
	"backend/internal/database/sqlc"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"backend/internal/security"
	"backend/internal/service"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sqlc-dev/pqtype"
)

// UserHandler holds dependencies needed by user endpoints.
type AuthHandler struct {
	DB          *pgxpool.Pool
	Queries     *sqlc.Queries
	ArgonHasher *security.ArgonHasher
}

type CSRFResponse struct {
	Token bool `json:"token"`
}

type AccountType struct {
	IsGoogle bool `json:"isGoogle"`
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
	Remember  bool   `json:"remember"`
}

type SigninPayload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Remember bool   `json:"remember"`
}

type UserInfo struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

type RoleData struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

func (h *AuthHandler) GetAccountType(w http.ResponseWriter, r *http.Request) {

	var payload SignupPayload

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

	payload.Email = strings.ToLower(strings.TrimSpace(payload.Email))

	user, err := h.Queries.GetUserByEmail(r.Context(), payload.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info("No existing account found for", "email", payload.Email)
		} else {
			slog.Error("email verification failed", "error", err)
			http.Error(w, "invalid email verification", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(
		AccountType{
			IsGoogle: user.GoogleAccount,
		},
	)

}

func (h *AuthHandler) SignUp(w http.ResponseWriter, r *http.Request) {

	removeAccount := func(Id pgtype.UUID, email string) {
		err := h.Queries.DeleteUser(r.Context(), sqlc.DeleteUserParams{
			ID:    Id,
			Email: email,
		})
		if err == nil {
			slog.Info("Account deleted")
		} else {
			slog.Error("Account was not deleted")
		}
	}

	var payload SignupPayload
	var hashedPassword string

	userAgent := r.Header.Get("User-Agent")
	slog.Info("SIGN UP Started")
	slog.Info("Remeber", "", payload.Remember)
	clientIP := security.GetClientIP(r)

	tokenService, err := service.Tokenkey()
	if err != nil {
		http.Error(w, "JWTPassword error", http.StatusInternalServerError)
		slog.Error("JWT Error")
		return
	}

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

	payload.Email = strings.ToLower(strings.TrimSpace(payload.Email))

	user, err := h.Queries.GetUserByEmail(r.Context(), payload.Email)
	not_exists := errors.Is(err, pgx.ErrNoRows)
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

	if not_exists {
		hashedPassword, err = service.HashPassword(h.ArgonHasher, payload.Password)
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
		UserName:      payload.FirstName,
		Surname:       payload.LastName,
		PasswordHash:  hashedPassword,
		Email:         payload.Email,
		Remember:      payload.Remember,
		GoogleAccount: false,
	})

	// 1. Create the JWT access token
	accessToken, err := tokenService.GenerateAccessToken(newUser.ID.String(), newUser.Email)
	if err != nil {
		slog.Error("failed to generate access token", "error", err)
		removeAccount(newUser.ID, newUser.Email)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 2. Create the opaque refresh token (raw for client, hash for DB)
	refreshToken, refreshHash, err := security.GenerateRefreshToken()
	if err != nil {
		slog.Error("failed to generate refresh token", "error", err)
		removeAccount(newUser.ID, newUser.Email)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if payload.Remember {
		// 3. Persist only the hash
		if err := h.Queries.InsertRefreshToken(r.Context(), sqlc.InsertRefreshTokenParams{
			UserID:    newUser.ID,
			TokenHash: refreshHash,
			ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(security.RefreshTokenTTL), Valid: true},
			UserAgent: pgtype.Text{String: userAgent, Valid: userAgent != ""},
			IpAddress: pgtype.Text{String: clientIP, Valid: clientIP != ""},
			IsRevoked: false,
			CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true},
		}); err != nil {
			slog.Error("failed to store refresh token", "error", err)
			removeAccount(newUser.ID, newUser.Email)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// 4. Send both raw tokens to the browser as HttpOnly cookies
		security.SetAuthCookies(w, accessToken, refreshToken)
		slog.Info("Auth cookies set for user", "email", newUser.Email, "id", newUser.ID)

	} else {
		preAuthToken, err := tokenService.GeneratePreAuthToken(newUser.ID.String(), newUser.Email)
		if err != nil {
			slog.Error("failed to generate pre-auth token", "error", err)
			removeAccount(newUser.ID, newUser.Email)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		security.SetPreAuthToken(w, preAuthToken)
		slog.Info("Pre-auth token set for user", "email", newUser.Email, "id", newUser.ID)
	}

	slog.Info("New user created", "email", newUser.Email, "id", newUser.ID)

	// 2. 🔍 CHECK IF COOKIES ARE INSERTED IN RESPONSE HEADERS
	slog.Info("Response Set-Cookie Headers", "cookies", w.Header()["Set-Cookie"])
	slog.Info("SIGN UP STOPED")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(
		UserInfo{
			Email: payload.Email,
			Name:  payload.FirstName + payload.LastName,
		},
	)
}

func (h *AuthHandler) CSRF_SignIn(w http.ResponseWriter, r *http.Request) {

	slog.Info("CSRF Start")
	slog.Info("Raw Cookie Header Received", "cookie_header", r.Header.Get("Cookie"))

	tokenService, err := service.Tokenkey()
	if err != nil {
		http.Error(w, "JWTPassword error", http.StatusInternalServerError)
		slog.Error("JWT Error")
		return
	}

	isAvailble, err := service.GetCSRFToken(tokenService, r)
	if err != nil {
		slog.Error("Not token given")
	}

	if !isAvailble {
		CSRFToken, err := tokenService.GenerateCSRFToken()
		if err != nil {
			http.Error(w, "CSRF error", http.StatusInternalServerError)
			slog.Error("CSRF error", "err", err)
			return
		}
		security.SetCSRFCookie(w, CSRFToken)
		// 2. 🔍 CHECK IF COOKIES ARE INSERTED IN RESPONSE HEADERS
		slog.Info("Response Set-Cookie Headers", "cookies", w.Header()["Set-Cookie"])

	} else {
		slog.Info("CSRF Token was already set")
	}

	slog.Info("CSRF Stop")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(CSRFResponse{
		Token: true,
	})
}

func (h *AuthHandler) SignIn(w http.ResponseWriter, r *http.Request) {

	slog.Info("SIGN IN STARTED")
	// Print raw Cookie header received by Go
	slog.Info("Raw Cookie Header Received", "cookie_header", r.Header.Get("Cookie"))

	var payload SigninPayload

	userAgent := r.Header.Get("User-Agent")
	clientIP := security.GetClientIP(r)

	slog.Info("Remeber", "", payload.Remember)

	tokenService, err := service.Tokenkey()
	if err != nil {
		http.Error(w, "JWTPassword error", http.StatusInternalServerError)
		slog.Error("JWT Error")
		return
	}

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

	payload.Email = strings.ToLower(strings.TrimSpace(payload.Email))

	user, err := h.Queries.GetUserByEmail(r.Context(), payload.Email)

	// 1. Determine target hash (use dummy hash if user does not exist)
	targetHash := user.PasswordHash
	slog.Info("Password: ", "", targetHash)
	userNotFound := errors.Is(err, pgx.ErrNoRows)

	if userNotFound {
		// Replace with a valid Argon2 hash string stored in your config/env
		targetHash = os.Getenv("DUMMY_PASSWORD_HASH")
	} else if err != nil {
		http.Error(w, `{"message":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	// 2. ALWAYS execute VerifyPassword with payload.Password and targetHash
	result, err := service.VerifyPassword(h.ArgonHasher, payload.Password, targetHash)
	if err != nil {
		http.Error(w, `{"message":"failed to verify password"}`, http.StatusInternalServerError)
		return
	}

	// 3. Reject if user was missing OR password check failed
	if userNotFound || !result {
		http.Error(w, `{"message":"invalid email or password"}`, http.StatusUnauthorized)
		return
	}

	err = h.Queries.UpdateRemember(r.Context(), sqlc.UpdateRememberParams{
		Remember: payload.Remember,
		ID:       user.ID,
		Email:    user.Email,
	})

	if err != nil {
		http.Error(w, `{"message":"impossible to save the remember stuff"}`, http.StatusUnauthorized)
		return
	}

	// Create the JWT access token
	accessToken, err := tokenService.GenerateAccessToken(user.ID.String(), user.Email)
	if err != nil {
		slog.Error("failed to generate access token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	addRefreshToken := func() {
		//Create Refresh Token
		refreshToken, refreshHash, err := security.GenerateRefreshToken()
		if err != nil {
			slog.Error("failed to generate refresh token", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := h.Queries.InsertRefreshToken(r.Context(), sqlc.InsertRefreshTokenParams{
			UserID:    user.ID,
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
		// 4. Send both raw tokens to the browser as HttpOnly cookies
		security.SetAuthCookies(w, accessToken, refreshToken)

	}

	hash, err := service.GetRefreshToken(tokenService, r)
	if err != nil {
		slog.Error("failed to get refresh token", "error", err)
	}

	if hash != "" {

		slog.Info("", "refreshTokenHash", hash)

		tokenData, err := h.Queries.GetRefreshTokenByHash(r.Context(), sqlc.GetRefreshTokenByHashParams{
			TokenHash: hash,
			IsRevoked: false,
		})
		if err != nil {
			slog.Error("failed to get refresh token by hash", "error", err)
		}

		err = h.Queries.DeleteRefreshToken(r.Context(), sqlc.DeleteRefreshTokenParams{
			UserID:    user.ID,
			TokenHash: tokenData.TokenHash,
		})
		if err != nil {
			slog.Error("failed to delete all refresh tokens", "error", err)
		}

	}

	if payload.Remember {
		addRefreshToken()
		slog.Info("Refresh token added for user", "email", user.Email, "id", user.ID)
	} else {
		preAuthToken, err := tokenService.GeneratePreAuthToken(user.ID.String(), user.Email)
		if err != nil {
			slog.Error("failed to generate pre-auth token", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		security.SetPreAuthToken(w, preAuthToken)
		slog.Info("Pre-auth token set for user", "email", user.Email, "id", user.ID)
	}

	slog.Info("SIGN IN STOPED")

	// 2. 🔍 CHECK IF COOKIES ARE INSERTED IN RESPONSE HEADERS
	slog.Info("Response Set-Cookie Headers", "cookies", w.Header()["Set-Cookie"])
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(
		UserInfo{
			Email: payload.Email,
			Name:  "",
		},
	)

}

func (h *AuthHandler) AuthMe(w http.ResponseWriter, r *http.Request) {

	slog.Info("AUTH ME STARTED")

	// Print raw Cookie header received by Go
	slog.Info("Raw Cookie Header Received", "cookie_header", r.Header.Get("Cookie"))

	tokenService, err := service.Tokenkey()
	if err != nil {
		http.Error(w, "JWTPassword error", http.StatusInternalServerError)
		slog.Error("JWT Error")
		return
	}

	getAccessToken, err := service.GetAccessToken(tokenService, r)

	if err != nil {
		slog.Error("failed to get access token", "error", err)
		http.Error(w, "internal error no access token found", http.StatusUnauthorized)
		return
	}

	if getAccessToken == "" {
		http.Error(w, `{"message":"no access token found"}`, http.StatusUnauthorized)
		return
	}

	claims, err := tokenService.ValidateAccessToken(getAccessToken)
	if err != nil {
		slog.Error("failed to validate access token", "error", err)
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}

	Id, err := service.ToPgUUID(claims.UserID)

	user, err := h.Queries.GetUserbyId(r.Context(), Id)
	if err != nil {
		slog.Error("failed to get user by ID", "error", err)
		http.Error(w, "internal error", http.StatusUnauthorized)
		return
	}

	slog.Info("Access token validated", "userID", claims.UserID, "email", claims.Email)

	slog.Info("AUTH ME STOPPED")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(
		UserInfo{
			Email: claims.Email,
			Name:  user.UserName + " " + user.Surname,
		},
	)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {

	slog.Info("REFRESH STARTED")

	// Print raw Cookie header received by Go
	slog.Info("Raw Cookie Header Received", "cookie_header", r.Header.Get("Cookie"))

	tokenService, err := service.Tokenkey()
	if err != nil {
		http.Error(w, "JWTPassword error", http.StatusInternalServerError)
		slog.Error("JWT Error")
		return
	}

	hash, err := service.GetRefreshToken(tokenService, r)
	if err != nil {
		slog.Error("failed to get refresh token", "error", err)
		http.Error(w, "internal error", http.StatusUnauthorized)
		return
	}

	if hash == "" {
		http.Error(w, `{"message":"no refresh token found"}`, http.StatusUnauthorized)
		return
	}

	slog.Info("", "refreshTokenHash", hash)

	tokenData, err := h.Queries.GetRefreshTokenByHash(r.Context(), sqlc.GetRefreshTokenByHashParams{
		TokenHash: hash,
		IsRevoked: false,
	})
	if err != nil {
		slog.Error("failed to get refresh token by hash", "error", err)
		http.Error(w, "internal error", http.StatusUnauthorized)
		return
	}

	if tokenData.TokenHash != hash {
		http.Error(w, `{"message":"invalid refresh token"}`, http.StatusUnauthorized)
		return
	}

	// Create the JWT access token
	accessToken, err := tokenService.GenerateAccessToken(tokenData.ID_2.String(), tokenData.Email)
	if err != nil {
		slog.Error("failed to generate access token", "error", err)
		http.Error(w, "internal error", http.StatusUnauthorized)
		return
	}

	security.SetAuthAccessToken(w, accessToken)

	slog.Info("Refresh token validated", "userID", tokenData.ID_2, "email", tokenData.Email)

	slog.Info("REFRESH STOPPED")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(
		UserInfo{
			Email: tokenData.Email,
			Name:  tokenData.UserName + " " + tokenData.Surname,
		},
	)

}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	slog.Info("LOGOUT STARTED")
	tokenService, err := service.Tokenkey()
	if err != nil {
		http.Error(w, "JWTPassword error", http.StatusInternalServerError)
		slog.Error("JWT Error")
		return
	}

	hash, err := service.GetRefreshToken(tokenService, r)
	if err != nil {
		slog.Error("failed to get refresh token", "error", err)
		http.Error(w, "internal error", http.StatusUnauthorized)
		return
	}

	if hash == "" {
		http.Error(w, `{"message":"no refresh token found"}`, http.StatusUnauthorized)
		return
	}

	tokenData, err := h.Queries.GetRefreshTokenByHash(r.Context(), sqlc.GetRefreshTokenByHashParams{
		TokenHash: hash,
		IsRevoked: false,
	})
	if err != nil {
		slog.Error("failed to get refresh token by hash", "error", err)
		http.Error(w, "internal error", http.StatusUnauthorized)
		return
	}

	if tokenData.TokenHash != hash {
		http.Error(w, `{"message":"invalid refresh token"}`, http.StatusUnauthorized)
		return
	}

	err = h.Queries.DeleteRefreshToken(r.Context(), sqlc.DeleteRefreshTokenParams{
		TokenHash: hash,
		UserID:    tokenData.ID_2,
	})

	if err != nil {
		slog.Error("failed to revoke refresh token", "error", err)
		http.Error(w, "internal error", http.StatusUnauthorized)
		return
	}

	security.ClearAuthCookies(w, false)

	slog.Info("Refresh token revoked", "userID", tokenData.ID_2, "email", tokenData.Email)
	slog.Info("LOGOUT STOPPED")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}
