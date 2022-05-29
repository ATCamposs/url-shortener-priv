package main

import (
	"log"

	"go-authentication-boilerplate/database"
	"go-authentication-boilerplate/presentation/fiber"
)

func main() {
	// Connect to Postgres
	database.ConnectToDB()

	// Create fiber presentation app
	app := fiber.CreateFiberServer()

	log.Fatal(app.Listen(":3000"))
}
