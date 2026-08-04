package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in a valid format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
	ErrPasswordTooLong     = errors.New("password exceeds maximum allowed length")
)

// Params holds the configuration for the Argon2id algorithm.
type Params struct {
	Memory      uint32 // RAM in KiB
	Iterations  uint32 // Number of passes
	Parallelism uint8  // Number of threads
	SaltLength  uint32 // Length of random salt in bytes
	KeyLength   uint32 // Length of generated hash key in bytes
}

// OWASP Recommended Default Parameters for Interactive Logins (2026/RFC 9106)
// Adjust Memory downwards (e.g., 16 * 1024) if running on low-resource micro-containers.
var DefaultParams = &Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// ArgonHasher manages hashing configuration and execution.
type ArgonHasher struct {
	params *Params
}

// NewArgonHasher returns a configured hasher instance.
func NewArgonHasher(params *Params) *ArgonHasher {
	if params == nil {
		params = DefaultParams
	}
	return &ArgonHasher{params: params}
}

// HashPassword generates a standard encoded Argon2id hash from a plain text password.
// Output format: $argon2id$v=19$m=65536,t=3,p=4$<b64-salt>$<b64-hash>
func (a *ArgonHasher) HashPassword(password string) (string, error) {
	// Guard against extremely long passwords attempting to exhaust CPU during hashing
	if len(password) > 4096 {
		return "", ErrPasswordTooLong
	}

	salt := make([]byte, a.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate cryptographically secure salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		a.params.Iterations,
		a.params.Memory,
		a.params.Parallelism,
		a.params.KeyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.params.Memory,
		a.params.Iterations,
		a.params.Parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// VerifyPassword checks if a plain-text password matches an encoded hash.
// It extracts the original salt and parameters encoded within the string to ensure valid comparison.
func (a *ArgonHasher) VerifyPassword(password, encodedHash string) (bool, error) {
	if len(password) > 4096 {
		return false, ErrPasswordTooLong
	}

	params, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Calculate the hash for the incoming password using extracted params & salt
	targetHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// Constant-time byte comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(hash, targetHash) == 1 {
		return true, nil
	}

	return false, nil
}

// decodeHash parses the standard encoded string format and extracts its components.
func decodeHash(encodedHash string) (params *Params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	if vals[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %s", vals[1])
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	params = &Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}
	params.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode hash: %w", err)
	}
	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}
