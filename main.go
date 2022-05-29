package main

import (
	"log"

	"go-authentication-boilerplate/database"
	"go-authentication-boilerplate/router"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// CreateServer creates a new Fiber instance
func CreateServer() *fiber.App {
	app := fiber.New()

	app.Use(cors.New())

	router.SetupRoutes(app)

	// 404 Handler
	app.Use(func(c *fiber.Ctx) error {
		return c.SendStatus(404) // => 404 "Not Found"
	})

	return app
}

func main() {
	// Connect to Postgres
	database.ConnectToDB()
	app := CreateServer()

	log.Fatal(app.Listen(":3000"))
}
