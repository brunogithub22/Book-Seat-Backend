CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE person (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_name VARCHAR(255) NOT NULL,
    user_role JSONB NOT NULL DEFAULT '{}'::jsonb,
    surname VARCHAR(255) NOT NULL,
    email TEXT NOT NULL
);

CREATE TABLE book (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    author VARCHAR(255) NOT NULL,
    category VARCHAR(255) NOT NULL,
    book_description TEXT NOT NULL
);

Create TABLE organization(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name_organization VARCHAR(255) NOT NULL,
    admin_id UUID NOT NULL REFERENCES person(id),
    role_name JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE room (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_name VARCHAR(255) NOT NULL,
    flor INT NOT NULL,
    n_seat INT NOT NULL
);

CREATE TABLE seat (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id UUID NOT NULL REFERENCES room(id),
    seat_description TEXT NOT NULL
);

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES person(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    user_agent TEXT,
    ip_address VARCHAR(45),
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast token lookups
CREATE INDEX idx_user_sessions_token_hash ON user_sessions(token_hash);

CREATE TABLE oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES person(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Ensures a user can only link a specific OAuth account once
    CONSTRAINT unique_provider_user UNIQUE (provider, provider_user_id)
);

-- Index for fast lookup when a user logs in via OAuth
CREATE INDEX idx_oauth_accounts_provider_user_id ON oauth_accounts(provider, provider_user_id);

Create TABLE user_book_booking (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reservation_date TIMESTAMP NOT NULL,
    expiration_date TIMESTAMP NOT NULL,
    book_id UUID NOT NULL REFERENCES book(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES person(id) ON DELETE CASCADE
);

Create TABLE user_book_manage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    book_id UUID NOT NULL REFERENCES book(id),
    user_id UUID NOT NULL REFERENCES person(id)
);

Create TABLE user_room_booking ( 
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reservation_date TIMESTAMP NOT NULL,
    room_id UUID NOT NULL REFERENCES room(id),
    user_id UUID NOT NULL REFERENCES person(id)
);

Create TABLE user_seat_booking (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reservation_date TIMESTAMP NOT NULL,
    seat_id UUID NOT NULL REFERENCES seat(id),
    user_id UUID NOT NULL REFERENCES person(id)
);