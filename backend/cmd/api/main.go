package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"backend/internal/database"
	"backend/internal/router"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := NewLogger()
	slog.SetDefault(logger) // lets you call slog.Info(...) anywhere without passing logger around

	// 1. Initialize DB with context timeout
	dbpool, err := database.InitDB(ctx)
	if err != nil {
		slog.Error("Failed to initialize database: %v", err)
	}
	defer dbpool.Close()

	// 2. Initialize Router
	appRouter := router.NewRouter(dbpool)

	// 3. Configure HTTP Server with explicit security timeouts
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      appRouter,
		ReadTimeout:  5 * time.Second,   // Prevents slow request attacks
		WriteTimeout: 10 * time.Second,  // Prevents hanging responses
		IdleTimeout:  120 * time.Second, // Controls keep-alive connections
	}

	go shutdown(srv)

	slog.Info("Server running on http://localhost:8080")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Server error: %v", err)
	}

	slog.Info("Server exited cleanly.")
}

func shutdown(srv *http.Server) {
	// 5. Graceful Shutdown Setup (Catch SIGINT and SIGTERM)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit // Block until signal is received

	slog.Info("Shutting down server gracefully...")

	// Give active requests 5 seconds to complete before forcing shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server forced to shutdown: %v", err)
	}
}
