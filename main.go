package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// Rate limiting simple y permisivo
var (
	requestCounts = make(map[string][]time.Time)
	requestMutex  = sync.Mutex{}
)

// Rate limiting MUY permisivo (solo para prevenir ataques masivos)
func SimpleRateLimitMiddleware(requestsPerMinute int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()
		
		requestMutex.Lock()
		
		// Limpiar requests antiguos (más de 1 minuto)
		if requests, exists := requestCounts[ip]; exists {
			var validRequests []time.Time
			for _, reqTime := range requests {
				if now.Sub(reqTime) < time.Minute {
					validRequests = append(validRequests, reqTime)
				}
			}
			requestCounts[ip] = validRequests
		}
		
		// Solo bloquear si hay MUCHAS requests (abuso extremo)
		if len(requestCounts[ip]) >= requestsPerMinute {
			requestMutex.Unlock()
			log.Printf("🚫 Extreme rate limit exceeded for IP: %s", ip)
			
			// IMPORTANTE: Asegurar CORS headers en respuesta de error
			c.Header("Access-Control-Allow-Origin", "https://frontcompiladores.duckdns.org")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
			
			c.JSON(http.StatusTooManyRequests, APIResponse{
				Success: false,
				Message: "Demasiadas solicitudes. Intenta más tarde.",
				Data:    nil,
			})
			c.Abort()
			return
		}
		
		// Agregar request actual
		requestCounts[ip] = append(requestCounts[ip], now)
		requestMutex.Unlock()
		
		c.Next()
	}
}

// Middleware SOLO para bloquear bots obvios (muy permisivo)
func BasicBotProtectionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userAgent := c.GetHeader("User-Agent")
		path := c.Request.URL.Path
		
		// NO aplicar a health check
		if path == "/health" {
			c.Next()
			return
		}
		
		// Solo bloquear bots MUY obvios
		if userAgent != "" {
			lowerUA := strings.ToLower(userAgent)
			if strings.Contains(lowerUA, "googlebot") ||
			   strings.Contains(lowerUA, "bingbot") ||
			   strings.Contains(lowerUA, "slurp") ||
			   (strings.Contains(lowerUA, "curl") && !strings.Contains(lowerUA, "mozilla")) ||
			   strings.Contains(lowerUA, "wget") ||
			   strings.Contains(lowerUA, "scanner") ||
			   strings.Contains(lowerUA, "attack") {
				log.Printf("🤖 Blocked obvious bot: %s", userAgent)
				
				// CORS headers en respuesta de error
				c.Header("Access-Control-Allow-Origin", "https://frontcompiladores.duckdns.org")
				c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
				
				c.JSON(http.StatusForbidden, APIResponse{
					Success: false,
					Message: "Acceso no autorizado",
					Data:    nil,
				})
				c.Abort()
				return
			}
		}
		
		c.Next()
	}
}

// Middleware de validación de entrada MÁS permisivo
func InputValidationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validar Content-Type SOLO para requests POST y con contenido
		if c.Request.Method == "POST" && c.Request.ContentLength > 0 {
			contentType := c.GetHeader("Content-Type")
			if !strings.Contains(contentType, "application/json") && 
			   !strings.Contains(contentType, "text/plain") {
				c.JSON(http.StatusBadRequest, APIResponse{
					Success: false,
					Message: "Content-Type inválido",
					Data:    nil,
				})
				c.Abort()
				return
			}
		}
		
		// Validar tamaño del request (muy permisivo)
		if c.Request.ContentLength > 10*1024*1024 { // 10MB max
			c.JSON(http.StatusRequestEntityTooLarge, APIResponse{
				Success: false,
				Message: "Request demasiado grande",
				Data:    nil,
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// Validación SQL MÁS permisiva (solo bloquear lo más peligroso)
func validateSQLQuery(query string) error {
	if len(query) == 0 {
		return fmt.Errorf("query vacía")
	}
	
	// Longitud máxima muy permisiva
	if len(query) > 5000 {
		return fmt.Errorf("query demasiado larga")
	}
	
	// Solo bloquear comandos EXTREMADAMENTE peligrosos
	query = strings.ToUpper(query)
	dangerous := []string{
		"DROP DATABASE",
		"DROP SCHEMA", 
		"SHUTDOWN",
		"EXEC XP_",
		"EXEC SP_",
	}
	
	for _, word := range dangerous {
		if strings.Contains(query, word) {
			log.Printf("🛡️ Blocked dangerous SQL: %s", word)
			return fmt.Errorf("comando no permitido")
		}
	}
	
	return nil
}

// Validar nombre de BD más permisivo
func validateDatabaseName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("nombre de base de datos requerido")
	}
	if len(name) > 100 {
		return fmt.Errorf("nombre demasiado largo")
	}
	return nil
}

// Handlers con validación mínima
func CreateDatabaseHandlerSecure(c *gin.Context) {
	var req DatabaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos: " + err.Error(),
			Data:    nil,
		})
		return
	}
	
	if err := validateDatabaseName(req.Database); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	CreateDatabaseHandler(c)
}

func UseDatabaseHandlerSecure(c *gin.Context) {
	var req DatabaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos: " + err.Error(),
			Data:    nil,
		})
		return
	}
	
	if err := validateDatabaseName(req.Database); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	UseDatabaseHandler(c)
}

func CreateTableHandlerSecure(c *gin.Context) {
	var req QueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos: " + err.Error(),
			Data:    nil,
		})
		return
	}
	
	if err := validateSQLQuery(req.Query); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	CreateTableHandler(c)
}

func InsertDataHandlerSecure(c *gin.Context) {
	var req QueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos: " + err.Error(),
			Data:    nil,
		})
		return
	}
	
	if err := validateSQLQuery(req.Query); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	InsertDataHandler(c)
}

func ModifyDataHandlerSecure(c *gin.Context) {
	var req QueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos: " + err.Error(),
			Data:    nil,
		})
		return
	}
	
	if err := validateSQLQuery(req.Query); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	ModifyDataHandler(c)
}

func DeleteDatabaseHandlerSecure(c *gin.Context) {
	var req DatabaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos: " + err.Error(),
			Data:    nil,
		})
		return
	}
	
	if err := validateDatabaseName(req.Database); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	DeleteDatabaseHandler(c)
}

func main() {
	// Inicializar la base de datos
	err := InitDB()
	if err != nil {
		log.Fatal("Error al inicializar la base de datos:", err)
	}
	defer CloseDB()

	// Configurar Gin en modo release
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Middleware de seguridad MUY permisivo
	r.Use(InputValidationMiddleware())
	r.Use(SimpleRateLimitMiddleware(300)) // 300 requests por minuto (muy permisivo)
	r.Use(BasicBotProtectionMiddleware()) // Solo bots obvios

	// CORS MUY permisivo
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"https://frontcompiladores.duckdns.org", "*"} // Temporalmente muy permisivo
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"*"} // Permitir todos los headers
	corsConfig.ExposeHeaders = []string{"*"}
	corsConfig.AllowCredentials = false
	corsConfig.MaxAge = 12 * time.Hour
	r.Use(cors.New(corsConfig))

	// Rutas de la API
	api := r.Group("/api")
	{
		// Análisis léxico/sintáctico sin restricciones
		api.POST("/lexical-analysis", LexicalAnalysisHandler)
		api.POST("/syntactic-analysis", SyntacticAnalysisHandler)
		
		// Operaciones de BD con validación mínima
		api.POST("/create-database", CreateDatabaseHandlerSecure)
		api.POST("/use-database", UseDatabaseHandlerSecure)
		api.POST("/create-table", CreateTableHandlerSecure)
		api.POST("/insert-data", InsertDataHandlerSecure)
		api.POST("/modify-data", ModifyDataHandlerSecure)
		api.POST("/delete-database", DeleteDatabaseHandlerSecure)
		api.GET("/database-info", GetDatabaseInfoHandler)
	}

	// Health check sin restricciones
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
			"secure": "permissive",
		})
	})

	// Puerto del servidor
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🚀 Servidor PERMISIVO iniciado en puerto %s", port)
	log.Printf("🛡️ Protección básica activada (anti-bots + rate limit: 300/min)")
	log.Printf("🌐 CORS muy permisivo para debugging")
	log.Printf("💡 Health check: /health")
	log.Fatal(http.ListenAndServe(":"+port, r))
}