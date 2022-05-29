package main

import (
	"log"

	"url-shortener/database"
	"url-shortener/presentation/fiber"
)

func main() {
	// Connect to Postgres
	database.ConnectToDB()

	// Create fiber presentation app
	app := fiber.CreateFiberServer()

	log.Fatal(app.Listen(":3000"))
}
