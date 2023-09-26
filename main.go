package main

import (
	"crypto/tls"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
)

var (
	db *redis.Client
)

func init() {
	db = redis.NewClient(&redis.Options{
		Addr:      addr + ":" + port,
		Password:  password,
		DB:        DB,
		TLSConfig: new(tls.Config),
	})
}

func main() {
	r := fiber.New()
	r.Post("/pki", CreatePKI)
	r.Post("/jwt", CreateJWT)
	r.Get("/.well-known/jwks.json", GetJWKs)
	r.Post("/validate", Validate)
	r.Listen(":8080")
}

func CreatePKI(c *fiber.Ctx) error {
	if err := createPKI(c.Context()); err != nil {
		c.Status(500)
		return c.SendString(err.Error())
	}
	return c.SendString("Success")
}

func CreateJWT(c *fiber.Ctx) error {
	token, err := createJWT(c.Context())
	if err != nil {
		c.Status(fiber.StatusInternalServerError)
		return c.SendString(err.Error())
	}
	return c.JSON(token)
}

func GetJWKs(c *fiber.Ctx) error {
	res, err := getJWKs(c.Context())
	if err != nil {
		c.Status(fiber.StatusInternalServerError)
		return c.SendString(err.Error())
	}
	return c.JSON(res)
}

func Validate(c *fiber.Ctx) error {
	fmt.Println(c.GetReqHeaders())
	header := c.GetReqHeaders()["Authorization"]
	var authHeader string
	if header != "" {
		authHeader = header[7:]
	} else {
		c.Status(fiber.StatusForbidden)
		return c.SendString("not exists authorization header")
	}
	claims, err := validate(c.Context(), authHeader)
	if err != nil {
		fmt.Println(err)
		c = c.Status(fiber.StatusUnauthorized)
		return c.SendString("not authorized")
	}
	return c.JSON(claims)
}
