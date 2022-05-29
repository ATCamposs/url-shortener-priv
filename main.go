package main

import (
	"log"

	"go-authentication-boilerplate/database"
	"go-authentication-boilerplate/router"
)

func main() {
	// Connect to Postgres
	database.ConnectToDB()

	// Create fiber presentation app
	app := router.CreateFiberServer()

	log.Fatal(app.Listen(":3000"))
}
