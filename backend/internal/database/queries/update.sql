-- name: UpdateRemember :exec
UPDATE person
SET remember = $1
WHERE id = $2 AND email = $3;