package security

import (
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	AccessTokenCookieName  = "access_token"
	RefreshTokenCookieName = "refresh_token"
	PreAuthTokenCookieName = "pre_auth_token"
	CSRFTokenCookieName    = "csrf_token"

	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour
	PreAuthTokenTTL = 1 * time.Minute
	CSRFTokenTTL    = 15 * time.Minute
)

// SetAuthCookies writes both the access and refresh token cookies to the response.
func SetAuthCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookieName,
		Value:    accessToken,
		Path:     "/",
		Expires:  time.Now().Add(AccessTokenTTL),
		HttpOnly: true,
		Secure:   false, // true in production (HTTPS), false only for local http dev
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    refreshToken,
		Path:     "/api/auth/refresh", // only sent to the refresh endpoint
		Expires:  time.Now().Add(RefreshTokenTTL),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}

func SetAuthAccessToken(w http.ResponseWriter, accessToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookieName,
		Value:    accessToken,
		Path:     "/",
		Expires:  time.Now().Add(AccessTokenTTL),
		HttpOnly: true,
		Secure:   false, // true in production (HTTPS), false only for local http dev
		SameSite: http.SameSiteLaxMode,
	})
}

func SetCSRFCookie(w http.ResponseWriter, csrfToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFTokenCookieName,
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(CSRFTokenTTL),
	})
}

func SetPreAuthToken(w http.ResponseWriter, authToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     PreAuthTokenCookieName,
		Value:    authToken,
		Path:     "/api/auth",
		Expires:  time.Now().Add(PreAuthTokenTTL),
		HttpOnly: true,
		Secure:   false, // true in production (HTTPS), false only for local http dev
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearAuthCookies expires both cookies immediately — used on logout.
func ClearAuthCookies(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    "",
		Path:     "/api/auth/refresh",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetClientIP extracts the real client IP, accounting for the nginx reverse proxy.
func GetClientIP(r *http.Request) string {
	// X-Real-IP is set explicitly by nginx to a single trusted value
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Fallback: X-Forwarded-For may contain a chain "client, proxy1, proxy2"
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0]) // first entry is the original client
	}

	// Last resort: direct connection, no proxy involved (e.g. local dev without nginx)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
