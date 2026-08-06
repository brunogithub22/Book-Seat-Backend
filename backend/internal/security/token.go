package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
)

// jwtSecret should come from an env var, loaded once at startup.
// e.g. os.Getenv("JWT_SECRET") — must be a long, random string, never committed.
type TokenService struct {
	jwtSecret []byte
}

func NewTokenService(secret string) *TokenService {
	return &TokenService{jwtSecret: []byte(secret)}
}

type AccessTokenClaims struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// GenerateAccessToken creates a short-lived signed JWT.
func (s *TokenService) GenerateAccessToken(userID, email string) (string, error) {
	claims := AccessTokenClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// ValidateAccessToken parses and verifies a JWT, returning its claims.
func (s *TokenService) ValidateAccessToken(tokenStr string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return s.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// GenerateRefreshToken creates a random opaque token (not a JWT).
// Returns the raw token (to send to the client) and its SHA-256 hash (to store in DB).
func GenerateRefreshToken() (raw string, hash string, err error) {
	b := make([]byte, 32) // 256 bits of randomness
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}

	raw = hex.EncodeToString(b)
	hashed := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(hashed[:])

	return raw, hash, nil
}

// HashToken hashes a raw refresh token the same way, used when validating
// an incoming refresh request against the stored hash.
func HashToken(raw string) string {
	hashed := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hashed[:])
}

// getTokenFromCookie legge il valore del cookie "access_token" dalla request
func getTokenFromCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", errors.New("no access_token cookie found")
		}
		return "", err
	}
	if cookie.Value == "" {
		return "", errors.New("access_token cookie is empty")
	}
	return cookie.Value, nil
}
