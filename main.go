package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// Inicializar la base de datos
	err := InitDB()
	if err != nil {
		log.Fatal("Error al inicializar la base de datos:", err)
	}
	defer CloseDB()

	// Configurar el router
	r := gin.Default()

	// Configurar CORS
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:5173"} // Ajusta según tu frontend
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	r.Use(cors.New(config))

	// Rutas de la API
	api := r.Group("/api")
	{
		api.POST("/lexical-analysis", LexicalAnalysisHandler)
		api.POST("/syntactic-analysis", SyntacticAnalysisHandler)
		api.POST("/create-database", CreateDatabaseHandler)
		api.POST("/use-database", UseDatabaseHandler)
		api.POST("/create-table", CreateTableHandler)
		api.POST("/insert-data", InsertDataHandler)
		api.POST("/modify-data", ModifyDataHandler)
		api.POST("/delete-database", DeleteDatabaseHandler)
		api.GET("/database-info", GetDatabaseInfoHandler)
	}

	// Puerto del servidor
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Puerto por defecto
	}

	log.Printf("Servidor iniciado en puerto %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}