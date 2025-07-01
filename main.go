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
		log.Printf("📥 [%s] %s %s", c.ClientIP(), c.Request.Method, c.Request.URL.Path)
		
		c.Next()
		
		// Log response
		log.Printf("📤 [%s] %s %s - Status: %d - Duration: %v", 
			c.ClientIP(), c.Request.Method, c.Request.URL.Path, c.Writer.Status(), time.Since(start))
	}
}

// UseDatabaseHandler con manejo de errores
func UseDatabaseHandlerSafe(c *gin.Context) {
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
	
	// Intentar usar la base de datos con manejo de errores
	log.Printf("🔄 Attempting to use database: %s", req.Database)
	
	err := UseDatabase(req.Database)
	if err != nil {
		log.Printf("❌ UseDatabase failed: %v", err)
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	log.Printf("✅ Database switch successful")
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Usando base de datos: " + req.Database,
		Data:    nil,
	})
}

// CreateTableHandler con manejo de errores
func CreateTableHandlerSafe(c *gin.Context) {
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
	
	log.Printf("✅ Request parsed, query: %s", req.Query)
	
	if req.Query == "" {
		log.Printf("❌ Query is empty")
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Query requerida",
			Data:    nil,
		})
		return
	}
	
	// Ejecutar query con manejo de errores
	log.Printf("🔄 Attempting to execute query")
	
	err := ExecuteQuery(req.Query)
	if err != nil {
		log.Printf("❌ ExecuteQuery failed: %v", err)
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	log.Printf("✅ Query executed successfully")
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Tabla creada exitosamente",
		Data:    nil,
	})
}

// InsertDataHandler con manejo de errores
func InsertDataHandlerSafe(c *gin.Context) {
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
	
	log.Printf("✅ Request parsed, query: %s", req.Query)
	
	if req.Query == "" {
		log.Printf("❌ Query is empty")
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Query requerida",
			Data:    nil,
		})
		return
	}
	
	// Ejecutar query con manejo de errores
	log.Printf("🔄 Attempting to execute insert query")
	
	err := ExecuteQuery(req.Query)
	if err != nil {
		log.Printf("❌ ExecuteQuery failed: %v", err)
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	log.Printf("✅ Insert query executed successfully")
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Datos insertados exitosamente",
		Data:    nil,
	})
}

// GetDatabaseInfoHandler con manejo de errores
func GetDatabaseInfoHandlerSafe(c *gin.Context) {
	log.Printf("🔍 GetDatabaseInfoHandler called")
	
	info, err := GetDatabaseInfo()
	if err != nil {
		log.Printf("❌ GetDatabaseInfo failed: %v", err)
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	log.Printf("✅ Database info retrieved successfully")
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Información de base de datos obtenida exitosamente",
		Data:    info,
	})
}

// ModifyDataHandler con manejo de errores
func ModifyDataHandlerSafe(c *gin.Context) {
	log.Printf("🔍 ModifyDataHandler called")
	
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
	
	log.Printf("✅ Request parsed, query: %s", req.Query)
	
	err := ExecuteQuery(req.Query)
	if err != nil {
		log.Printf("❌ ExecuteQuery failed: %v", err)
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	log.Printf("✅ Modify query executed successfully")
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Datos modificados exitosamente",
		Data:    nil,
	})
}

// CreateDatabaseHandler con manejo de errores
func CreateDatabaseHandlerSafe(c *gin.Context) {
	log.Printf("🔍 CreateDatabaseHandler called")
	
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
	
	err := CreateDatabase(req.Database)
	if err != nil {
		log.Printf("❌ CreateDatabase failed: %v", err)
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	log.Printf("✅ Database created successfully: %s", req.Database)
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Base de datos creada exitosamente: " + req.Database,
		Data:    nil,
	})
}

// DeleteDatabaseHandler con manejo de errores
func DeleteDatabaseHandlerSafe(c *gin.Context) {
	log.Printf("🔍 DeleteDatabaseHandler called")
	
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
	
	err := DeleteDatabase(req.Database)
	if err != nil {
		log.Printf("❌ DeleteDatabase failed: %v", err)
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	log.Printf("✅ Database deleted successfully: %s", req.Database)
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Base de datos eliminada exitosamente: " + req.Database,
		Data:    nil,
	})
}

func main() {
	// Configurar logging detallado
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	log.Printf("🚀 Starting server with error handling...")
	
	// Inicializar la base de datos
	log.Printf("🔄 Initializing database...")
	err := InitDB()
	if err != nil {
		log.Fatal("❌ Error al inicializar la base de datos:", err)
	}
	defer CloseDB()
	log.Printf("✅ Database initialized")

	// Configurar Gin en modo release
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Middleware de logging
	r.Use(DetailedLoggingMiddleware())

	// CORS permisivo
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"*"}
	corsConfig.ExposeHeaders = []string{"*"}
	corsConfig.AllowCredentials = false
	r.Use(cors.New(corsConfig))

	// Rutas de la API con handlers SEGUROS
	api := r.Group("/api")
	{
		// Análisis sin modificar (estos funcionan)
		api.POST("/lexical-analysis", LexicalAnalysisHandler)
		api.POST("/syntactic-analysis", SyntacticAnalysisHandler)
		
		// Operaciones de BD con manejo de errores COMPLETO
		api.POST("/create-database", CreateDatabaseHandlerSafe)
		api.POST("/use-database", UseDatabaseHandlerSafe)
		api.POST("/create-table", CreateTableHandlerSafe)
		api.POST("/insert-data", InsertDataHandlerSafe)
		api.POST("/modify-data", ModifyDataHandlerSafe)
		api.POST("/delete-database", DeleteDatabaseHandlerSafe)
		api.GET("/database-info", GetDatabaseInfoHandlerSafe)
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
			"fixed":  true,
		})
	})

	// Puerto del servidor
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🚀 Server with ERROR HANDLING started on port %s", port)
	log.Printf("🔧 All handlers now have proper error handling")
	log.Printf("💡 Health check: /health")
	
	log.Fatal(http.ListenAndServe(":"+port, r))
}