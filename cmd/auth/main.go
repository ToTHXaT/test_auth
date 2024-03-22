package main

import (
	"github.com/ToTHXaT/test_auth/config"
	"github.com/ToTHXaT/test_auth/internal/routes"
	"github.com/gin-gonic/gin"
	"log"
)

func main() {
	config.LoadConfig()
	app := gin.Default()

	app.POST("/login", routes.Login)
	app.GET("/refresh", routes.Refresh)

	log.Fatal(app.Run(":8000"))
}
