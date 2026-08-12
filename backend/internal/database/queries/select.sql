-- name: GetAllFromBooks :many
SELECT * FROM book;

-- name: GetUserByEmail :one
SELECT id, email, password_hash, google_account
FROM person
WHERE email = $1;

-- name: GetRefreshToken :one
Select id,token_hash
From user_sessions 
Where user_id = $1 AND is_revoked = $2;

-- name: GetUserbyId :one
Select user_name,surname 
From person 
Where id = $1;

-- name: GetRefreshTokenByHash :one
Select u_s.id,u_s.token_hash,p.id,p.user_name,p.surname,p.email
From user_sessions as u_s,person as p
Where u_s.user_id = p.id AND u_s.token_hash = $1 AND u_s.is_revoked = $2; 