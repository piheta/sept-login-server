package services

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	weberrors "github.com/piheta/sept-login-server/errors"
	"github.com/piheta/sept-login-server/repos"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
)

type AuthService struct {
	userRepo *repos.UserRepo
}

func NewAuthService(userRepo *repos.UserRepo) *AuthService {
	return &AuthService{
		userRepo: userRepo,
	}
}

// Load the private key from a PEM file
func (as *AuthService) loadPrivateKey() (*ecdsa.PrivateKey, error) {
	keyData, err := os.ReadFile("private_key.pem")
	if err != nil {
		return nil, fmt.Errorf("could not read private key file: %v", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %v", err)
	}

	return privateKey, nil
}

func LoadPublicKey() (*ecdsa.PublicKey, string, error) {
	keyData, err := os.ReadFile("public_key.pem")
	if err != nil {
		return nil, "", fmt.Errorf("could not read public key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, "", fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaPub, string(keyData), nil
}

func (as *AuthService) HashPassword(password string) (string, error) {
	// Generate salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Hash password using Argon2
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Encode salt and hash to base64
	encodedSalt := base64.StdEncoding.EncodeToString(salt)
	encodedHash := base64.StdEncoding.EncodeToString(hash)

	// Concatenate salt and hash with a separator
	hashedPassword := fmt.Sprintf("%s$%s", encodedSalt, encodedHash)

	return hashedPassword, nil
}

func (as *AuthService) verifyPassword(password, hashedPassword string) (bool, error) {
	// Split hashed password into salt and hash
	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid hashed password format")
	}
	encodedSalt := parts[0]
	encodedHash := parts[1]

	// Decode salt and hash from base64
	salt, err := base64.StdEncoding.DecodeString(encodedSalt)
	if err != nil {
		return false, fmt.Errorf("failed to decode jwt salt and hash")
	}

	// Hash provided password with extracted salt
	computedHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Compare computed hash with stored hash
	return base64.StdEncoding.EncodeToString(computedHash) == encodedHash, nil
}

func (as *AuthService) Login(email, pass, public_key string) (*string, error) {
	user, err := as.userRepo.GetUserByEmail(email)
	if err != nil {
		return nil, err
	}

	passwordMatchesHash, err := as.verifyPassword(pass, user.Password)
	if err != nil {
		return nil, weberrors.NewError(500, err.Error())
	}

	if !passwordMatchesHash {
		return nil, weberrors.NewError(401, "invalid password")
	}

	claims := jwt.MapClaims{
		"id":         user.ID,
		"name":       user.Name,
		"exp":        time.Now().Add(time.Hour * 72).Unix(),
		"public_key": public_key,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Generate encoded token and send it as response
	private_key, err := as.loadPrivateKey()
	if err != nil {
		return nil, weberrors.NewError(500, "failed load key")
	}
	jwtToken, err := token.SignedString(private_key)
	if err != nil {
		return nil, weberrors.NewError(500, "failed to sign token")
	}

	return &jwtToken, nil
}
