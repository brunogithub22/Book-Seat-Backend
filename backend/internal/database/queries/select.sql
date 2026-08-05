-- name: GetAllFromBooks :many
SELECT * FROM book;

-- name: GetUserByEmail :one
SELECT id, email, password_hash
FROM person
WHERE email = $1;