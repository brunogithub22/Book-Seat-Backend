package middleware

import (
	"crypto/subtle"
	"net/http"
)

func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("csrf_token")
		if err != nil || cookie.Value == "" {
			http.Error(w, "missing csrf cookie", http.StatusForbidden)
			return // "not reachable" — request rejected here
		}

		header := r.Header.Get("X-CSRF-Token")
		if header == "" {
			http.Error(w, "missing csrf header", http.StatusForbidden)
			return // "not reachable" — request rejected here
		}

		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			http.Error(w, "mismatch cookie and header", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r) // both present and matching — proceed
	})
}
