-- name: GetAllFromBooks :many
SELECT * FROM book;

-- name: GetUserByEmail :one
SELECT id, email, password_hash
FROM person
WHERE email = $1;

-- name: GetRefreshToken :one
Select id,token_hash
From user_sessions 
Where user_id = $1 AND is_revoked = $2;