package main

import (
	"net/smtp"

	"github.com/gin-gonic/gin"
	"github.com/katomaso/gin-auth"
)

func t(s string) string {
	return s
}

func main() {
	auth := gin_auth.New("localhost:8080", "example.com", "wow-so-secure")
	auth.AddProvider("facebook", "1284421665399747", "664bd4487d5695d1c19639181e7c8228")
	auth.AddEmailProvider("login@exaple.com", t("Your code for login is {{.Code}}"), `{{.Code}}`, 6, "example.org",
		smtp.PlainAuth("", "mailtrap", "mailtrap", "localhost:9025"))

	router := gin.Default()
	router.GET("/auth", auth.Index())
	router.GET("/auth/*provider", auth.Providers())
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, map[string]string{"hello": "world"})
	})
	router.GET("/public", func(c *gin.Context) {
		c.JSON(200, map[string]string{"hello": "public"})
	})
	router.Use(auth.Required())
	router.GET("/secret", func(c *gin.Context) {
		c.JSON(200, map[string]string{"hello": "secret"})
	})
	router.Run(":8080")
}
