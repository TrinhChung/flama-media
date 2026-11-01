package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidTokenFormat = errors.New("invalid token format, expected payload.signature")
	ErrInvalidSignature   = errors.New("invalid token signature, verification failed")
	ErrTokenExpired       = errors.New("token has expired")
	ErrInvalidPayload     = errors.New("cannot decode token payload")
)

type UploadTicket struct {
	UserID   int64  `json:"user_id"`
	MaxBytes int64  `json:"max_bytes"`
	Exp      int64  `json:"exp"`
	Action   string `json:"action"`
}

// VerifyToken validates an HMAC-SHA256 presigned token against the shared secret.
// Format: <base64url_json_payload>.<hex_hmac_signature>
func VerifyToken(token string, secret string) (*UploadTicket, error) {
	if secret == "" || len(token) > 4096 {
		return nil, ErrInvalidSignature
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, ErrInvalidTokenFormat
	}

	b64Payload := parts[0]
	signatureHex := parts[1]

	// 1. Verify HMAC Signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(b64Payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signatureHex), []byte(expectedSig)) {
		return nil, ErrInvalidSignature
	}

	// 2. Decode payload
	payloadBytes, err := base64.URLEncoding.DecodeString(b64Payload)
	if err != nil {
		// Try RawURLEncoding without padding
		payloadBytes, err = base64.RawURLEncoding.DecodeString(b64Payload)
		if err != nil {
			return nil, ErrInvalidPayload
		}
	}

	var ticket UploadTicket
	if err := json.Unmarshal(payloadBytes, &ticket); err != nil {
		return nil, ErrInvalidPayload
	}

	// 3. Verify expiration
	if time.Now().Unix() >= ticket.Exp {
		return nil, ErrTokenExpired
	}

	return &ticket, nil
}
