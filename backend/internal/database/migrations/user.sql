CREATE TABLE person (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_name VARCHAR(255) NOT NULL,
    surname VARCHAR(255) NOT NULL,
    email TEXT NOT NULL
);