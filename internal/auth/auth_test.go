package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT_Valid(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"
	expiresIn := time.Hour

	tokenString, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}
	if tokenString == "" {
		t.Fatal("MakeJWT returned empty token string")
	}

	validatedUserID, err := ValidateJWT(tokenString, secret)
	if err != nil {
		t.Fatalf("ValidateJWT failed for valid token: %v", err)
	}

	if validatedUserID != userID {
		t.Errorf("Validated UserID (%s) does not match original UserID (%s)", validatedUserID, userID)
	}
}

func TestValidateJWT_Expired(t *testing.T) {
	userID := uuid.New()
	secret := "test-secret"
	expiresIn := -time.Hour // Expired an hour ago

	tokenString, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	_, err = ValidateJWT(tokenString, secret)
	if err == nil {
		t.Fatal("ValidateJWT succeeded for expired token, expected error")
	}
	// You might want to check for a specific error type or message here
	// e.g., if !errors.Is(err, jwt.ErrTokenExpired) { ... }
	t.Logf("Received expected error for expired token: %v", err)
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	userID := uuid.New()
	correctSecret := "correct-secret"
	wrongSecret := "wrong-secret"
	expiresIn := time.Hour

	tokenString, err := MakeJWT(userID, correctSecret, expiresIn)
	if err != nil {
		t.Fatalf("MakeJWT failed: %v", err)
	}

	_, err = ValidateJWT(tokenString, wrongSecret)
	if err == nil {
		t.Fatal("ValidateJWT succeeded with wrong secret, expected error")
	}
	// You might want to check for a specific error type or message here
	// e.g., if !errors.Is(err, jwt.ErrSignatureInvalid) { ... }
	t.Logf("Received expected error for wrong secret: %v", err)
}

func TestPasswordHashing(t *testing.T) {
	password := "mysecretpassword"

	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if hashedPassword == "" {
		t.Fatal("HashPassword returned empty string")
	}
	if hashedPassword == password {
		t.Fatal("Hashed password is the same as original password")
	}

	// Test correct password
	err = CheckPasswordHash(hashedPassword, password)
	if err != nil {
		t.Errorf("CheckPasswordHash failed for correct password: %v", err)
	}

	// Test incorrect password
	wrongPassword := "notthepassword"
	err = CheckPasswordHash(hashedPassword, wrongPassword)
	if err == nil {
		t.Error("CheckPasswordHash succeeded for incorrect password, expected error")
	}
}
