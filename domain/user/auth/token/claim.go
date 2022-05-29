package token

import "github.com/golang-jwt/jwt/v4"

// Claims represent the structure of the JWT token
type Claim struct {
	ID uint `gorm:"primaryKey"`
	jwt.StandardClaims
}
