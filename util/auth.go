package util

import (
	"strings"
	"time"
	db "url-shortener/database"
	"url-shortener/domain/user/auth/token"
	"url-shortener/provider/date"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

var jwtKey = []byte(db.PRIVKEY)

// GenerateTokens generates the access and refresh tokens
func GenerateTokens(uuid string) (string, string) {
	claim, accessToken := GenerateAccessClaims(uuid)
	refreshToken := GenerateRefreshClaims(claim)

	return accessToken, refreshToken
}

// GenerateAccessClaims returns a claim and a acess_token string
func GenerateAccessClaims(uuid string) (*token.Claim, string) {

	t := date.New().Now()
	claim := &token.Claim{
		StandardClaims: jwt.StandardClaims{
			Issuer:    uuid,
			ExpiresAt: t.Add(1 * time.Hour).Unix(),
			Subject:   "access_token",
			IssuedAt:  t.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claim)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		panic(err)
	}

	return claim, tokenString
}

// GenerateRefreshClaims returns refresh_token
func GenerateRefreshClaims(cl *token.Claim) string {
	result := db.DB.Where(&token.Claim{
		StandardClaims: jwt.StandardClaims{
			Issuer: cl.Issuer,
		},
	}).Find(&token.Claim{})

	// checking the number of refresh tokens stored.
	// If the number is higher than 3, remove all the refresh tokens and leave only new one.
	if result.RowsAffected > 3 {
		db.DB.Where(&token.Claim{StandardClaims: jwt.StandardClaims{Issuer: cl.Issuer}}).Delete(&token.Claim{})
	}

	t := date.New().Now()
	refreshClaim := &token.Claim{
		StandardClaims: jwt.StandardClaims{
			Issuer:    cl.Issuer,
			ExpiresAt: t.Add(10 * 24 * time.Hour).Unix(),
			Subject:   "refresh_token",
			IssuedAt:  t.Unix(),
		},
	}

	// create a claim on DB
	db.DB.Create(&refreshClaim)

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, refreshClaim)
	refreshTokenString, err := refreshToken.SignedString(jwtKey)
	if err != nil {
		panic(err)
	}

	return refreshTokenString
}

// SecureAuth returns a middleware which secures all the private routes
func SecureAuth() func(*fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		accessToken := strings.Split(c.Get("Authorization"), "Bearer ")[1]
		claims := new(token.Claim)
		token, err := jwt.ParseWithClaims(accessToken, claims,
			func(token *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})
		if err != nil {
			panic(err)
		}
		if token.Valid {
			if claims.ExpiresAt < time.Now().Unix() {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error":   true,
					"general": "Token Expired",
				})
			}
		} else if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				// this is not even a token, we should delete the cookies here
				c.ClearCookie("access_token", "refresh_token")
				return c.SendStatus(fiber.StatusForbidden)
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				// Token is either expired or not active yet
				return c.SendStatus(fiber.StatusUnauthorized)
			} else {
				// cannot handle this token
				c.ClearCookie("access_token", "refresh_token")
				return c.SendStatus(fiber.StatusForbidden)
			}
		}

		c.Locals("id", claims.Issuer)
		return c.Next()
	}
}

// GetAuthCookies sends two cookies of type access_token and refresh_token
func GetAuthCookies(accessToken, refreshToken string) (*fiber.Cookie, *fiber.Cookie) {
	accessCookie := &fiber.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HTTPOnly: true,
		Secure:   true,
	}

	refreshCookie := &fiber.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Expires:  time.Now().Add(10 * 24 * time.Hour),
		HTTPOnly: true,
		Secure:   true,
	}

	return accessCookie, refreshCookie
}
