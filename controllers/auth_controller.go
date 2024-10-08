package controllers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	weberrors "github.com/piheta/sept-login-server/errors"
	"github.com/piheta/sept-login-server/models"
	"github.com/piheta/sept-login-server/services"
)

// Shared auth controller-logic for mapping jwt claim to object
func mapReqToJWT(c *fiber.Ctx) *models.JWT {
	claims := c.Locals("user").(*jwt.Token).Claims.(jwt.MapClaims)

	idStr, ok := claims["id"].(string)
	if !ok {
		return nil
	}

	nameStr, ok := claims["name"].(string)
	if !ok {
		return nil
	}

	subjectStr, ok := claims["sub"].(string)
	if !ok {
		return nil
	}

	pubKeyStr, ok := claims["public_key"].(string)
	if !ok {
		return nil
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil
	}

	jwt := models.JWT{ID: id, Name: nameStr, Sub: subjectStr, PublicKey: pubKeyStr}
	return &jwt
}

type AuthController struct {
	authService *services.AuthService
}

func NewAuthController(authService *services.AuthService) *AuthController {
	return &AuthController{authService: authService}
}

// Login handles the authentication process
// @Summary Login
// @Description Authenticates a user and returns a JWT token
// @Tags Auth
// @Accept json
// @Produce json
// @Param loginRequest body LoginRequest true "Login Request"
// @Success 200
// @Failure 400
// @Failure 404
// @Failure 401
// @Failure 500
// @Router /api/login [post]
func (ac *AuthController) Login(c *fiber.Ctx) error {
	var loginRequest models.LoginRequest
	if err := c.BodyParser(&loginRequest); err != nil {
		return weberrors.NewError(400, err.Error())
	}

	token, err := ac.authService.Login(loginRequest.Email, loginRequest.Password, loginRequest.PublicKey)
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{"token": token})
}

// GetJwtPubKey handles the retrieval of the JWT public key
// @Summary Get JWT Public Key
// @Description Retrieves the public key used to verify JWT signatures in the sept client
// @Tags Auth
// @Accept json
// @Produce json
// @Success 200
// @Failure 500
// @Router /api/key [get]
func (ac *AuthController) GetJwtPubKey(c *fiber.Ctx) error {
	_, pub_key, err := services.LoadPublicKey()
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{"public_key": pub_key})
}
