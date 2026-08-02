package main

import (
	"context"
	"errors"
	"log"
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

	// 1. Initialize DB with context timeout
	dbpool, err := database.InitDB(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
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

	log.Println("Server running on http://localhost:8080")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Server error: %v", err)
	}

	log.Println("Server exited cleanly.")
}

func shutdown(srv *http.Server) {
	// 5. Graceful Shutdown Setup (Catch SIGINT and SIGTERM)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit // Block until signal is received

	log.Println("Shutting down server gracefully...")

	// Give active requests 5 seconds to complete before forcing shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
}
