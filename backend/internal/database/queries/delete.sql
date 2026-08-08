-- name: DeleteUser :exec
DELETE FROM person
WHERE id = $1 AND email = $2;

-- name: DeleteRefreshToken :exec
Delete From user_sessions
Where user_id = $1 AND token_hash = $2; 