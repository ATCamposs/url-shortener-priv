package fiber

import (
	"url-shortener/util"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// USER handles all the user routes
var USER fiber.Router

// CreateFiberServer creates a new Fiber instance
func CreateFiberServer() *fiber.App {
	app := fiber.New()

	app.Use(cors.New())

	SetupRoutes(app)

	// 404 Handler
	app.Use(func(c *fiber.Ctx) error {
		return c.SendStatus(404) // => 404 "Not Found"
	})

	return app
}

// SetupRoutes setups all the Routes
func SetupRoutes(app *fiber.App) {
	api := app.Group("/api")

	USER = api.Group("/user")
	USER.Post("/signup", CreateUser)              // Sign Up a user
	USER.Post("/signin", LoginUser)               // Sign In a user
	USER.Get("/get-access-token", GetAccessToken) // returns a new access_token

	// privUser handles all the private user routes that requires authentication
	privUser := USER.Group("/private")
	privUser.Use(util.SecureAuth()) // middleware to secure all routes for this group
	privUser.Get("/user", GetUserData)
}
