package fiber

import (
	"time"
	db "url-shortener/database"
	"url-shortener/domain/user/auth/token"
	"url-shortener/domain/user/entity"
	"url-shortener/provider/date"
	"url-shortener/service"
	"url-shortener/util"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

var jwtKey = []byte(db.PRIVKEY)

// CreateUser route registers a User into the database
func CreateUser(c *fiber.Ctx) error {
	u := new(entity.User)

	if err := c.BodyParser(u); err != nil {
		return c.JSON(fiber.Map{
			"error": true,
			"input": "Please review your input",
		})
	}

	u, err := service.Register(u)
	if err != nil {
		c.JSON(err)
	}

	// setting up the authorization cookies
	accessToken, refreshToken := util.GenerateTokens(u.UUID.String())
	accessCookie, refreshCookie := util.GetAuthCookies(accessToken, refreshToken)
	c.Cookie(accessCookie)
	c.Cookie(refreshCookie)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// LoginUser route logins a user in the app
func LoginUser(c *fiber.Ctx) error {
	input := new(util.LoginInput)

	if err := c.BodyParser(input); err != nil {
		return c.JSON(fiber.Map{"error": true, "input": "Please review your input"})
	}

	u, err := service.Login(input)
	if err != nil {
		c.JSON(err)
	}

	// setting up the authorization cookies
	accessToken, refreshToken := util.GenerateTokens(u.UUID.String())
	accessCookie, refreshCookie := util.GetAuthCookies(accessToken, refreshToken)
	c.Cookie(accessCookie)
	c.Cookie(refreshCookie)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// GetAccessToken generates and sends a new access token iff there is a valid refresh token
func GetAccessToken(c *fiber.Ctx) error {

	reToken := new(util.RefreshToken)
	if err := c.BodyParser(reToken); err != nil {
		return c.JSON(fiber.Map{"error": true, "input": "Please review your input"})
	}

	refreshToken := reToken.RefreshToken

	u, err := service.GetAccessToken(refreshToken)
	if err != nil {
		c.JSON(err)
	}

	refreshClaims := new(token.Claim)
	actualToken, _ := jwt.ParseWithClaims(refreshToken, refreshClaims,
		func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	if res := db.DB.Where(
		"expires_at = ? AND issued_at = ? AND issuer = ?",
		refreshClaims.ExpiresAt, refreshClaims.IssuedAt, refreshClaims.Issuer,
	).First(&token.Claim{}); res.RowsAffected <= 0 {
		// no such refresh token exist in the database
		c.ClearCookie("access_token", "refresh_token")
		return c.SendStatus(fiber.StatusForbidden)
	}

	if actualToken.Valid {
		if refreshClaims.ExpiresAt < date.New().Now().Unix() {
			// refresh token is expired
			c.ClearCookie("access_token", "refresh_token")
			return c.SendStatus(fiber.StatusForbidden)
		}
	} else {
		// malformed refresh token
		c.ClearCookie("access_token", "refresh_token")
		return c.SendStatus(fiber.StatusForbidden)
	}

	_, accessToken := util.GenerateAccessClaims(refreshClaims.Issuer)

	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HTTPOnly: true,
		Secure:   true,
	})

	return c.JSON(fiber.Map{"access_token": accessToken})
}

/*
	PRIVATE ROUTES
*/

// GetUserData returns the details of the user signed in
func GetUserData(c *fiber.Ctx) error {
	id := c.Locals("id")

	u := new(entity.User)
	if res := db.DB.Where("uuid = ?", id).First(&u); res.RowsAffected <= 0 {
		return c.JSON(fiber.Map{"error": true, "general": "Cannot find the User"})
	}

	return c.JSON(u)
}
