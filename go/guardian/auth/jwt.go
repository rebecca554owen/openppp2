package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Claims struct {
	Subject   string    `json:"sub,omitempty"`
	ExpiresAt time.Time `json:"-"`
	IssuedAt  time.Time `json:"-"`
}

type jwtPayload struct {
	Subject   string `json:"sub,omitempty"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
}

func GenerateToken(secret string, expiryHours int) (string, error) {
	if secret == "" {
		return "", errors.New("secret is required")
	}
	if expiryHours <= 0 {
		expiryHours = 24
	}

	now := time.Now().UTC()
	payload := jwtPayload{
		Subject:   "guardian",
		ExpiresAt: now.Add(time.Duration(expiryHours) * time.Hour).Unix(),
		IssuedAt:  now.Unix(),
	}

	headerBytes, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	unsigned := encodedHeader + "." + encodedPayload

	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(unsigned)); err != nil {
		return "", err
	}
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return unsigned + "." + sig, nil
}

func ValidateToken(tokenString string, secret string) (*Claims, error) {
	if secret == "" {
		return nil, errors.New("secret is required")
	}
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	unsigned := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(unsigned)); err != nil {
		return nil, err
	}
	expectedSig := mac.Sum(nil)
	providedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if !hmac.Equal(providedSig, expectedSig) {
		return nil, errors.New("invalid token signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var payload jwtPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("decode payload json: %w", err)
	}

	claims := &Claims{
		Subject:   payload.Subject,
		ExpiresAt: time.Unix(payload.ExpiresAt, 0).UTC(),
		IssuedAt:  time.Unix(payload.IssuedAt, 0).UTC(),
	}
	if time.Now().UTC().After(claims.ExpiresAt) {
		return nil, errors.New("token expired")
	}

	return claims, nil
}
