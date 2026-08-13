package database

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// InitDB initializes and configures a thread-safe PostgreSQL connection pool.
func InitDB(ctx context.Context) (*pgxpool.Pool, error) {
	// 1. Read the connection string from environment variables

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable is not set")
	}

	// 2. Parse the configuration string into a pgxpool.Config struct
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse DATABASE_URL: %w", err)
	}

	// 3. Configure production connection pool settings
	config.MaxConns = 50                       // Maximum number of active connections in the pool
	config.MinConns = 5                        // Minimum idle connections to keep open
	config.MaxConnLifetime = 1 * time.Hour     // Close and recreate connections after 1 hour
	config.MaxConnIdleTime = 30 * time.Minute  // Close connections idle for longer than 30 minutes
	config.HealthCheckPeriod = 1 * time.Minute // Interval to check health of idle connections

	// 4. Create the connection pool with a timeout context
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(pingCtx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	// 5. Verify the database is reachable before returning the pool
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close() // Clean up pool if ping fails
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	return pool, nil
}
