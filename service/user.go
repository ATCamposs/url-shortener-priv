package service

import (
	"errors"
	"math/rand"
	"url-shortener/database"
	"url-shortener/domain/user/auth/token"
	"url-shortener/domain/user/entity"
	"url-shortener/provider/date"
	"url-shortener/util"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

func Register(u *entity.User) (*entity.User, error) {
	// validate if the email, username and password are in correct format
	validationErrors := util.ValidateRegister(u)
	if validationErrors.Err {
		err, _ := json.Marshal(validationErrors)
		return u, errors.New(string(err))
	}

	if count := database.DB.Where(&entity.User{Email: u.Email}).First(new(entity.User)).RowsAffected; count > 0 {
		validationErrors.Err, validationErrors.Email = true, "Email is already registered"
	}
	if count := database.DB.Where(&entity.User{Username: u.Username}).First(new(entity.User)).RowsAffected; count > 0 {
		validationErrors.Err, validationErrors.Username = true, "Username is already registered"
	}
	if validationErrors.Err {
		err, _ := json.Marshal(validationErrors)
		return u, errors.New(string(err))
	}

	// Hashing the password with a random salt
	password := []byte(u.Password)
	hashedPassword, err := bcrypt.GenerateFromPassword(
		password,
		rand.Intn(bcrypt.MaxCost-bcrypt.MinCost)+bcrypt.MinCost,
	)

	if err != nil {
		panic(err)
	}
	u.Password = string(hashedPassword)

	// Add created and updated dates
	now := date.New().NowInRfc3339()
	u.CreatedAt, u.UpdatedAt = now, now

	if err := database.DB.Create(&u).Error; err != nil {
		errMap := make(map[string]string)
		errMap["error"] = "true"
		errMap["general"] = "Something went wrong, please try again later."
		jsonErr, _ := json.Marshal(errMap)
		return u, errors.New(string(jsonErr))
	}

	return u, nil
}

func Login(input *util.LoginInput) (*entity.User, error) {
	u := new(entity.User)
	if res := database.DB.Where(
		&entity.User{Email: input.Identity}).Or(
		&entity.User{Username: input.Identity},
	).First(&u); res.RowsAffected <= 0 {
		return invalidCredentials()
	}

	// Comparing the password with the hash
	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(input.Password)); err != nil {
		return invalidCredentials()
	}

	return u, nil
}

// CONTINUAR AQUI AMANHA, verificar os tokens
func GetAccessToken(refreshToken string) (string, error) {
	refreshClaims := new(token.Claim)
	actualToken, _ := jwt.ParseWithClaims(refreshToken, refreshClaims,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(database.PRIVKEY), nil
		})

	if res := database.DB.Where(
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
}

func invalidCredentials() (*entity.User, error) {
	errMap := make(map[string]string)
	errMap["error"] = "true"
	errMap["general"] = "Invalid Credentials."
	jsonErr, _ := json.Marshal(errMap)
	return &entity.User{}, errors.New(string(jsonErr))
}
