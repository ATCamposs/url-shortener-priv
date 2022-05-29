package models

import (
	"url-shortener/provider/date"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Base contains common columns for all tables
type Base struct {
	UUID      uuid.UUID `json:"id" gorm:"primaryKey;autoIncrement:false"`
	CreatedAt string    `json:"created_at"`
	UpdatedAt string    `json:"updated_at"`
}

// BeforeCreate will set Base struct before every insert
func (base *Base) BeforeCreate(tx *gorm.DB) error {
	// generate a uuid and save that as a string
	uuid := uuid.New()
	base.UUID = uuid

	// generate timestamps
	t := date.New().NowInRfc3339()
	base.CreatedAt, base.UpdatedAt = t, t

	return nil
}

// AfterUpdate will update the Base struct after every update
func (base *Base) AfterUpdate(tx *gorm.DB) error {
	// update timestamps
	base.UpdatedAt = date.New().NowInRfc3339()
	return nil
}
