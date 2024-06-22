package controllers

import (
	"auth-api/models"
	"auth-api/services"
	"auth-api/utils"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var users = []models.User{
	{Username: "user1", Password: "$2a$14$zp.7QZkXsQw9.PdDpi.OMOVslXxwAsj1aYPmf1QuJwPkmMqaSYR2m", Email: "user1@example.com", Name: "User One"}, // Password: "password1"
	{Username: "user2", Password: "$2a$14$zp.7QZkXsQw9.PdDpi.OMOVslXxwAsj1aYPmf1QuJwPkmMqaSYR2m", Email: "user2@example.com", Name: "User Two"}, // Password: "password1"
}

type RegisterInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Name     string `json:"name" binding:"required"`
}

type LoginInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type ForgotPasswordInput struct {
	Email string `json:"email" binding:"required"`
}

type UpdateProfileInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

func Register(c *gin.Context) {
	var input RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, _ := utils.HashPassword(input.Password)
	user := models.User{
		Username: input.Username,
		Password: hashedPassword,
		Email:    input.Email,
		Name:     input.Name,
	}

	users = append(users, user)

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func Login(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	for _, u := range users {
		if u.Username == input.Username {
			user = u
			break
		}
	}

	if user.Username == "" || !utils.CheckPasswordHash(input.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":       user.Username,
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func ForgotPassword(c *gin.Context) {
	var input ForgotPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	for _, u := range users {
		if u.Email == input.Email {
			user = u
			break
		}
	}

	if user.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email not found"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 1).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := services.SendResetPasswordEmail(user.Email, tokenString); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Reset password email sent"})
}

func UpdateProfile(c *gin.Context) {
	var input UpdateProfileInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	username, _ := c.Get("username")
	var user *models.User
	for i, u := range users {
		if u.Username == username {
			user = &users[i]
			break
		}
	}

	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	if input.Username != "" {
		user.Username = input.Username
	}
	if input.Password != "" {
		hashedPassword, _ := utils.HashPassword(input.Password)
		user.Password = hashedPassword
	}
	if input.Email != "" {
		user.Email = input.Email
	}
	if input.Name != "" {
		user.Name = input.Name
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}
