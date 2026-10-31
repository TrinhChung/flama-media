package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestVerifyToken_Success(t *testing.T) {
	secret := "test-secret-key-12345"
	payload := UploadTicket{
		UserID:   42,
		MaxBytes: 10485760,
		Exp:      time.Now().Unix() + 300,
		Action:   "upload",
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	b64Payload := base64.RawURLEncoding.EncodeToString(raw)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(b64Payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	token := b64Payload + "." + sig

	ticket, err := VerifyToken(token, secret)
	if err != nil {
		t.Fatalf("expected valid token, got: %v", err)
	}

	if ticket.UserID != 42 {
		t.Errorf("expected UserID 42, got %d", ticket.UserID)
	}
	if ticket.MaxBytes != 10485760 {
		t.Errorf("expected MaxBytes 10485760, got %d", ticket.MaxBytes)
	}
}

func TestVerifyToken_Expired(t *testing.T) {
	secret := "test-secret-key-12345"
	payload := UploadTicket{
		UserID:   42,
		MaxBytes: 10485760,
		Exp:      time.Now().Unix() - 10, // Expired 10s ago
		Action:   "upload",
	}

	raw, _ := json.Marshal(payload)
	b64Payload := base64.RawURLEncoding.EncodeToString(raw)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(b64Payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	token := b64Payload + "." + sig

	_, err := VerifyToken(token, secret)
	if err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got: %v", err)
	}
}

func TestVerifyToken_TamperedSignature(t *testing.T) {
	secret := "test-secret-key-12345"
	payload := UploadTicket{
		UserID:   42,
		MaxBytes: 10485760,
		Exp:      time.Now().Unix() + 300,
	}

	raw, _ := json.Marshal(payload)
	b64Payload := base64.RawURLEncoding.EncodeToString(raw)
	fakeSig := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	token := b64Payload + "." + fakeSig

	_, err := VerifyToken(token, secret)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}
