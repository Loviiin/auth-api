package routes

import (
	"auth-api/controllers"
	"auth-api/middleware"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(router *gin.Engine) {
	api := router.Group("/api")
	{
		api.POST("/register", controllers.Register)
		api.POST("/login", controllers.Login)
		api.POST("/forgot-password", controllers.ForgotPassword)

		auth := api.Group("/")
		auth.Use(middleware.AuthMiddleware())
		{
			auth.PUT("/update-profile", controllers.UpdateProfile)
		}
	}
}
