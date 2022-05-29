package user

import "github.com/google/uuid"

// User represents a User schema
type User struct {
	UUID      uuid.UUID `json:"id"`
	CreatedAt string    `json:"created_at"`
	UpdatedAt string    `json:"updated_at"`
	Email     string    `json:"email" gorm:"unique"`
	Username  string    `json:"username" gorm:"unique"`
	Password  string    `json:"-"`
}
