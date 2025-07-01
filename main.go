package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// Middleware de logging detallado
func DetailedLoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		// Log request
		log.Printf("📥 [%s] %s %s - Headers: %v", 
			c.ClientIP(), c.Request.Method, c.Request.URL.Path, c.Request.Header)
		
		c.Next()
		
		// Log response
		log.Printf("📤 [%s] %s %s - Status: %d - Duration: %v", 
			c.ClientIP(), c.Request.Method, c.Request.URL.Path, c.Writer.Status(), time.Since(start))
	}
}

// Handler con logs detallados para use-database
func UseDatabaseHandlerWithLogs(c *gin.Context) {
	log.Printf("🔍 UseDatabaseHandler called")
	
	var req DatabaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("❌ Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Error al parsear JSON: " + err.Error(),
			Data:    nil,
		})
		return
	}
	
	log.Printf("✅ Request parsed: %+v", req)
	
	if req.Database == "" {
		log.Printf("❌ Database name is empty")
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Nombre de base de datos requerido",
			Data:    nil,
		})
		return
	}
	
	log.Printf("🔄 Calling original UseDatabaseHandler")
	
	// Llamar al handler original
	UseDatabaseHandler(c)
	
	log.Printf("✅ UseDatabaseHandler completed")
}

// Handler con logs para create-table
func CreateTableHandlerWithLogs(c *gin.Context) {
	log.Printf("🔍 CreateTableHandler called")
	
	var req QueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("❌ Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Error al parsear JSON: " + err.Error(),
			Data:    nil,
		})
		return
	}
	
	log.Printf("✅ Request parsed: %+v", req)
	
	if req.Query == "" {
		log.Printf("❌ Query is empty")
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Query requerida",
			Data:    nil,
		})
		return
	}
	
	log.Printf("🔄 Calling original CreateTableHandler")
	
	// Llamar al handler original
	CreateTableHandler(c)
	
	log.Printf("✅ CreateTableHandler completed")
}

// Handler con logs para database-info
func GetDatabaseInfoHandlerWithLogs(c *gin.Context) {
	log.Printf("🔍 GetDatabaseInfoHandler called")
	
	log.Printf("🔄 Calling original GetDatabaseInfoHandler")
	
	// Llamar al handler original
	GetDatabaseInfoHandler(c)
	
	log.Printf("✅ GetDatabaseInfoHandler completed")
}

// Handler con logs para insert-data
func InsertDataHandlerWithLogs(c *gin.Context) {
	log.Printf("🔍 InsertDataHandler called")
	
	var req QueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("❌ Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Error al parsear JSON: " + err.Error(),
			Data:    nil,
		})
		return
	}
	
	log.Printf("✅ Request parsed: %+v", req)
	
	log.Printf("🔄 Calling original InsertDataHandler")
	
	// Llamar al handler original
	InsertDataHandler(c)
	
	log.Printf("✅ InsertDataHandler completed")
}

func main() {
	// Configurar logging detallado
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	log.Printf("🚀 Starting server with detailed debugging...")
	
	// Inicializar la base de datos
	log.Printf("🔄 Initializing database...")
	err := InitDB()
	if err != nil {
		log.Fatal("❌ Error al inicializar la base de datos:", err)
	}
	defer CloseDB()
	log.Printf("✅ Database initialized")

	// Configurar Gin en modo debug para ver más detalles
	gin.SetMode(gin.DebugMode)
	r := gin.Default()

	// Middleware de logging detallado
	r.Use(DetailedLoggingMiddleware())

	// CORS súper permisivo
	log.Printf("🌐 Setting up CORS...")
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true // Permitir TODOS los orígenes
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"*"}
	corsConfig.ExposeHeaders = []string{"*"}
	corsConfig.AllowCredentials = false
	r.Use(cors.New(corsConfig))
	log.Printf("✅ CORS configured (allow all origins)")

	// Rutas de la API con handlers con logs
	log.Printf("🔄 Setting up API routes...")
	api := r.Group("/api")
	{
		// Análisis sin modificar
		api.POST("/lexical-analysis", func(c *gin.Context) {
			log.Printf("🔍 LexicalAnalysisHandler called")
			LexicalAnalysisHandler(c)
		})
		api.POST("/syntactic-analysis", func(c *gin.Context) {
			log.Printf("🔍 SyntacticAnalysisHandler called")
			SyntacticAnalysisHandler(c)
		})
		
		// Operaciones de BD con logs detallados
		api.POST("/create-database", func(c *gin.Context) {
			log.Printf("🔍 CreateDatabaseHandler called")
			CreateDatabaseHandler(c)
		})
		api.POST("/use-database", UseDatabaseHandlerWithLogs)
		api.POST("/create-table", CreateTableHandlerWithLogs)
		api.POST("/insert-data", InsertDataHandlerWithLogs)
		api.POST("/modify-data", func(c *gin.Context) {
			log.Printf("🔍 ModifyDataHandler called")
			ModifyDataHandler(c)
		})
		api.POST("/delete-database", func(c *gin.Context) {
			log.Printf("🔍 DeleteDatabaseHandler called")
			DeleteDatabaseHandler(c)
		})
		api.GET("/database-info", GetDatabaseInfoHandlerWithLogs)
	}
	log.Printf("✅ API routes configured")

	// Health check con logs
	r.GET("/health", func(c *gin.Context) {
		log.Printf("🔍 Health check called")
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
			"debug":  true,
		})
	})

	// Puerto del servidor
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🚀 Starting server on port %s with DEBUG MODE", port)
	log.Printf("🌐 CORS: Allow all origins")
	log.Printf("📋 All requests will be logged in detail")
	log.Printf("💡 Health check: /health")
	
	log.Fatal(http.ListenAndServe(":"+port, r))
}