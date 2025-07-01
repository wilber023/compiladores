package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Configuración de seguridad backend-only
type SecurityConfig struct {
	MaxRequestsPerMin   int
	MaxConcurrentConns  int
	EnableIPWhitelist   bool
	AllowedIPs          []string
	RequestTimeout      time.Duration
	MaxQueryLength      int
	TrustedOrigin       string
}

// Rate limiter por IP
var (
	rateLimiters = make(map[string]*rate.Limiter)
	rateMutex    = sync.Mutex{}
	activeConns  = make(map[string]int)
	connMutex    = sync.Mutex{}
)

// Rate limiting middleware
func RateLimitMiddleware(requestsPerMinute int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		
		rateMutex.Lock()
		limiter, exists := rateLimiters[ip]
		if !exists {
			limiter = rate.NewLimiter(rate.Limit(requestsPerMinute)/60, requestsPerMinute)
			rateLimiters[ip] = limiter
		}
		rateMutex.Unlock()
		
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, APIResponse{
				Success: false,
				Message: "Demasiadas solicitudes. Intenta más tarde.",
				Data:    nil,
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// Middleware para validar origen (Referer)
func TrustedOriginMiddleware(trustedOrigin string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Permitir requests directos (para testing)
		referer := c.GetHeader("Referer")
		origin := c.GetHeader("Origin")
		
		// Si viene de tu frontend específico, permitir
		if strings.Contains(referer, trustedOrigin) || strings.Contains(origin, trustedOrigin) {
			c.Next()
			return
		}
		
		// Si no tiene referer/origin, verificar User-Agent para detectar bots
		userAgent := c.GetHeader("User-Agent")
		if userAgent == "" || 
		   strings.Contains(strings.ToLower(userAgent), "bot") ||
		   strings.Contains(strings.ToLower(userAgent), "crawler") ||
		   strings.Contains(strings.ToLower(userAgent), "spider") {
			c.JSON(http.StatusForbidden, APIResponse{
				Success: false,
				Message: "Acceso no autorizado",
				Data:    nil,
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// Middleware de whitelist de IPs
func IPWhitelistMiddleware(allowedIPs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(allowedIPs) == 0 {
			c.Next()
			return
		}
		
		clientIP := c.ClientIP()
		allowed := false
		
		for _, ip := range allowedIPs {
			if clientIP == ip || strings.HasPrefix(clientIP, ip) {
				allowed = true
				break
			}
		}
		
		if !allowed {
			c.JSON(http.StatusForbidden, APIResponse{
				Success: false,
				Message: "IP no autorizada",
				Data:    nil,
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// Middleware para limitar conexiones concurrentes
func ConcurrentConnectionsMiddleware(maxConns int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		
		connMutex.Lock()
		if activeConns[ip] >= maxConns {
			connMutex.Unlock()
			c.JSON(http.StatusTooManyRequests, APIResponse{
				Success: false,
				Message: "Demasiadas conexiones concurrentes",
				Data:    nil,
			})
			c.Abort()
			return
		}
		activeConns[ip]++
		connMutex.Unlock()
		
		defer func() {
			connMutex.Lock()
			activeConns[ip]--
			if activeConns[ip] <= 0 {
				delete(activeConns, ip)
			}
			connMutex.Unlock()
		}()
		
		c.Next()
	}
}

// Middleware de validación de entrada
func InputValidationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Validar Content-Type para requests POST
		if c.Request.Method == "POST" {
			contentType := c.GetHeader("Content-Type")
			if !strings.Contains(contentType, "application/json") {
				c.JSON(http.StatusBadRequest, APIResponse{
					Success: false,
					Message: "Content-Type debe ser application/json",
					Data:    nil,
				})
				c.Abort()
				return
			}
		}
		
		// Validar tamaño del request
		if c.Request.ContentLength > 1024*1024 { // 1MB max
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

// Middleware de timeout
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return gin.TimeoutWithHandler(timeout, func(c *gin.Context) {
		c.JSON(http.StatusRequestTimeout, APIResponse{
			Success: false,
			Message: "Request timeout",
			Data:    nil,
		})
	})
}

// Validación adicional para queries SQL
func validateSQLQuery(query string) error {
	// Limpiar la query
	query = strings.TrimSpace(strings.ToUpper(query))
	
	// Longitud máxima
	if len(query) > 2000 {
		return fmt.Errorf("query demasiado larga")
	}
	
	// Prevenir múltiples statements
	if strings.Contains(query, ";") && !strings.HasSuffix(query, ";") {
		return fmt.Errorf("múltiples statements no permitidos")
	}
	
	// Palabras prohibidas
	dangerous := []string{
		"DROP DATABASE",
		"DROP SCHEMA", 
		"TRUNCATE",
		"SHUTDOWN",
		"PRAGMA",
		"ATTACH",
		"DETACH",
		"VACUUM",
		"REINDEX",
	}
	
	for _, word := range dangerous {
		if strings.Contains(query, word) {
			return fmt.Errorf("comando no permitido: %s", word)
		}
	}
	
	return nil
}

// Validar nombre de base de datos
func validateDatabaseName(name string) error {
	if len(name) == 0 || len(name) > 50 {
		return fmt.Errorf("nombre de base de datos debe tener entre 1 y 50 caracteres")
	}
	
	// Validar caracteres permitidos
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || char == '_') {
			return fmt.Errorf("nombre contiene caracteres no permitidos")
		}
	}
	
	return nil
}

// Handlers seguros que envuelven los originales
func CreateDatabaseHandlerSecure(c *gin.Context) {
	var req DatabaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos",
			Data:    nil,
		})
		return
	}
	
	// Validar nombre de BD
	if err := validateDatabaseName(req.Database); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}
	
	// Llamar al handler original
	CreateDatabaseHandler(c)
}

func UseDatabaseHandlerSecure(c *gin.Context) {
	var req DatabaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos",
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
			Message: "Datos de entrada inválidos",
			Data:    nil,
		})
		return
	}
	
	if err := validateSQLQuery(req.Query); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: fmt.Sprintf("Query inválida: %s", err.Error()),
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
			Message: "Datos de entrada inválidos",
			Data:    nil,
		})
		return
	}
	
	if err := validateSQLQuery(req.Query); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: fmt.Sprintf("Query inválida: %s", err.Error()),
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
			Message: "Datos de entrada inválidos",
			Data:    nil,
		})
		return
	}
	
	if err := validateSQLQuery(req.Query); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: fmt.Sprintf("Query inválida: %s", err.Error()),
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
			Message: "Datos de entrada inválidos",
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

// Funciones auxiliares
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvArrayOrDefault(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}

func main() {
	// Configuración de seguridad sin API Key
	config := SecurityConfig{
		MaxRequestsPerMin:   getEnvIntOrDefault("MAX_REQUESTS_PER_MIN", 60),  // Más permisivo
		MaxConcurrentConns:  getEnvIntOrDefault("MAX_CONCURRENT_CONNS", 10),  // Más permisivo
		EnableIPWhitelist:   getEnvBoolOrDefault("ENABLE_IP_WHITELIST", false),
		AllowedIPs:          getEnvArrayOrDefault("ALLOWED_IPS", []string{}),
		RequestTimeout:      time.Duration(getEnvIntOrDefault("REQUEST_TIMEOUT_SECONDS", 30)) * time.Second,
		MaxQueryLength:      getEnvIntOrDefault("MAX_QUERY_LENGTH", 2000),
		TrustedOrigin:       getEnvOrDefault("TRUSTED_ORIGIN", "frontcompiladores.duckdns.org"),
	}
	
	log.Printf("🛡️  Protección backend activada")
	log.Printf("⚡ Rate limit: %d requests/min", config.MaxRequestsPerMin)
	log.Printf("🔗 Conexiones concurrentes max: %d", config.MaxConcurrentConns)
	log.Printf("🌐 Origen confiable: %s", config.TrustedOrigin)
	
	// Inicializar la base de datos
	err := InitDB()
	if err != nil {
		log.Fatal("Error al inicializar la base de datos:", err)
	}
	defer CloseDB()
	
	// Configurar Gin
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	
	// Middleware de seguridad global
	r.Use(TimeoutMiddleware(config.RequestTimeout))
	r.Use(InputValidationMiddleware())
	r.Use(RateLimitMiddleware(config.MaxRequestsPerMin))
	r.Use(ConcurrentConnectionsMiddleware(config.MaxConcurrentConns))
	r.Use(TrustedOriginMiddleware(config.TrustedOrigin))
	
	if config.EnableIPWhitelist {
		r.Use(IPWhitelistMiddleware(config.AllowedIPs))
		log.Printf("🚫 IP Whitelist habilitado: %v", config.AllowedIPs)
	}
	
	// Configurar CORS para tu frontend
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"https://frontcompiladores.duckdns.org"}
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	corsConfig.ExposeHeaders = []string{"Content-Length"}
	corsConfig.AllowCredentials = false
	corsConfig.MaxAge = 12 * time.Hour
	r.Use(cors.New(corsConfig))
	
	// Rutas de la API con handlers seguros
	api := r.Group("/api")
	{
		// Handlers originales para análisis (sin modificaciones SQL)
		api.POST("/lexical-analysis", LexicalAnalysisHandler)
		api.POST("/syntactic-analysis", SyntacticAnalysisHandler)
		
		// Handlers seguros para operaciones de BD
		api.POST("/create-database", CreateDatabaseHandlerSecure)
		api.POST("/use-database", UseDatabaseHandlerSecure)
		api.POST("/create-table", CreateTableHandlerSecure)
		api.POST("/insert-data", InsertDataHandlerSecure)
		api.POST("/modify-data", ModifyDataHandlerSecure)
		api.POST("/delete-database", DeleteDatabaseHandlerSecure)
		api.GET("/database-info", GetDatabaseInfoHandler)
	}
	
	// Ruta de health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
			"secure": true,
		})
	})
	
	// Puerto del servidor
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("🚀 Servidor seguro iniciado en puerto %s", port)
	log.Printf("🌐 CORS configurado para: https://frontcompiladores.duckdns.org")
	log.Printf("💡 Health check disponible en: /health")
	log.Fatal(http.ListenAndServe(":"+port, r))
}