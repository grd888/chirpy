-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password, is_chirpy_red)
VALUES ($1, $2, $3, $4, $5, false)
RETURNING id, email, is_chirpy_red, created_at, updated_at;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT id, email, hashed_password, is_chirpy_red, created_at, updated_at FROM users WHERE email = $1;

-- name: UpdateUser :one
UPDATE users
SET email = $2, hashed_password = $3, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpgradeUserToChirpyRed :one
UPDATE users
SET is_chirpy_red = true, updated_at = NOW()
WHERE id = $1
RETURNING *;
