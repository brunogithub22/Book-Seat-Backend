#!/usr/bin/env bash

set -e # Exit immediately if a command exits with a non-zero status

# Configuration variables
PG_VERSION="18"
DB_PATH="./data/db"
LOG_PATH="./log"
LOG_FILE="${LOG_PATH}/logfile"
DB_NAME="bookingplatform"
DB_USER="bruno"
PORT="5433"
SOCKET_DIR="/tmp"
DUMP_FILE="book_seat_full.dump"
MIGRATIONS_PATH="./backend/internal/database/migrations"

# Colors for pretty output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}===> Starting Database Setup for Book-Seat <===${NC}"

# 1. Create necessary folders if they don't exist
echo -e "${YELLOW}[1/6] Creating directories...${NC}"
mkdir -p "$DB_PATH" "$LOG_PATH"

# 2. Initialize PostgreSQL Data Directory if not already initialized
if [ ! -f "$DB_PATH/PG_VERSION" ]; then
    echo -e "${YELLOW}[2/6] Initializing new PostgreSQL cluster with initdb...${NC}"
    "/usr/lib/postgresql/${PG_VERSION}/bin/initdb" -D "$DB_PATH" -U "$DB_USER"

    # Configure custom port and socket in postgresql.conf
    echo -e "${YELLOW}Configuring port ${PORT} and socket directory ${SOCKET_DIR}...${NC}"
    echo "port = ${PORT}" >> "$DB_PATH/postgresql.conf"
    echo "unix_socket_directories = '${SOCKET_DIR}'" >> "$DB_PATH/postgresql.conf"
else
    echo -e "${GREEN}[2/6] PostgreSQL cluster already initialized.${NC}"
fi

# 3. Start PostgreSQL Server if not running
if ! pg_isready -h "$SOCKET_DIR" -p "$PORT" > /dev/null 2>&1; then
    echo -e "${YELLOW}[3/6] Starting PostgreSQL server...${NC}"
    "/usr/lib/postgresql/${PG_VERSION}/bin/pg_ctl" -D "$DB_PATH" -l "$LOG_FILE" start
    sleep 2
else
    echo -e "${GREEN}[3/6] PostgreSQL server is already running.${NC}"
fi

# 4. Create Database if it does not exist
if ! psql -h "$SOCKET_DIR" -p "$PORT" -U "$DB_USER" -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    echo -e "${YELLOW}[4/6] Creating database '${DB_NAME}'...${NC}"
    createdb -h "$SOCKET_DIR" -p "$PORT" -U "$DB_USER" "$DB_NAME"
else
    echo -e "${GREEN}[4/6] Database '${DB_NAME}' already exists.${NC}"
fi

# 5. Run Database Migrations
if command -v migrate &> /dev/null; then
    echo -e "${YELLOW}[5/6] Running golang-migrate migrations...${NC}"
    migrate -database "postgres://${DB_USER}@localhost:${PORT}/${DB_NAME}?sslmode=disable&host=${SOCKET_DIR}" -path "$MIGRATIONS_PATH" up || true
else
    echo -e "${YELLOW}[5/6] Warning: 'migrate' CLI tool not found. Skipping migrations up step.${NC}"
fi

# 6. Restore Data Dump (if file exists)
if [ -f "$DUMP_FILE" ]; then
    echo -e "${YELLOW}[6/6] Restoring data from '${DUMP_FILE}'...${NC}"
    pg_restore -h "$SOCKET_DIR" -p "$PORT" -U "$DB_USER" -d "$DB_NAME" --clean --if-exists -v "$DUMP_FILE" || true
    echo -e "${GREEN}Data restored successfully!${NC}"
else
    echo -e "${YELLOW}[6/6] Dump file '${DUMP_FILE}' not found. Skipping restore step.${NC}"
fi

echo -e "${GREEN}===> Setup complete! Database is ready to use. <===${NC}"