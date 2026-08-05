-- name: DeleteUser :exec
DELETE FROM person
WHERE id = $1 AND email = $2;