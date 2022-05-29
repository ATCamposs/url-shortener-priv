package util

import (
	"url-shortener/domain/user"

	valid "github.com/asaskevich/govalidator"
)

// IsEmpty checks if a string is empty
func IsEmpty(str string) (bool, string) {
	if valid.HasWhitespaceOnly(str) && str != "" {
		return true, "Must not be empty"
	}

	return false, ""
}

// ValidateRegister func validates the body of user for registration
func ValidateRegister(u *user.User) *user.UserErrors {
	e := &user.UserErrors{}
	e.Err, e.Username = IsEmpty(u.Username)

	if !valid.IsEmail(u.Email) {
		e.Err, e.Email = true, "Must be a valid email"
	}

	// TODO create new validation for password
	//re := regexp.MustCompile("\\d") // regex check for at least one integer in string
	//if !(len(u.Password) >= 8 && valid.HasLowerCase(u.Password) && valid.HasUpperCase(u.Password)) {
	//	e.Err, e.Password = true, "Length of password should be atleast 8 and it must be a combination of uppercase letters, lowercase letters and numbers"
	//}

	return e
}
