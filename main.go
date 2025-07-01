package main

import (
	"context"
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

// Rate limiting middleware MÁS ESTRICTO
func RateLimitMiddleware(requestsPerMinute int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		
		rateMutex.Lock()
		limiter, exists := rateLimiters[ip]
		if !exists {
			// Crear un limiter más estricto: requests/minuto dividido por 4 para hacer burst más pequeño
			limiter = rate.NewLimiter(rate.Limit(requestsPerMinute)/60, max(1, requestsPerMinute/4))
			rateLimiters[ip] = limiter
		}
		rateMutex.Unlock()
		
		if !limiter.Allow() {
			log.Printf("🚫 Rate limit exceeded for IP: %s", ip)
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

// Helper function for max
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Middleware para validar origen (Referer) MÁS ESTRICTO
func TrustedOriginMiddleware(trustedOrigin string) gin.HandlerFunc {
	return func(c *gin.Context) {
		referer := c.GetHeader("Referer")
		origin := c.GetHeader("Origin")
		userAgent := c.GetHeader("User-Agent")
		
		// Log para debugging
		log.Printf("🔍 Request from IP: %s, Origin: %s, Referer: %s, UA: %s", 
			c.ClientIP(), origin, referer, userAgent)
		
		// Verificar User-Agent malicioso PRIMERO
		if userAgent == "" || 
		   strings.Contains(strings.ToLower(userAgent), "bot") ||
		   strings.Contains(strings.ToLower(userAgent), "crawler") ||
		   strings.Contains(strings.ToLower(userAgent), "spider") ||
		   strings.Contains(strings.ToLower(userAgent), "curl") ||
		   strings.Contains(strings.ToLower(userAgent), "wget") {
			log.Printf("🤖 Blocked malicious User-Agent: %s", userAgent)
			c.JSON(http.StatusForbidden, APIResponse{
				Success: false,
				Message: "Acceso no autorizado - Bot detectado",
				Data:    nil,
			})
			c.Abort()
			return
		}
		
		// Verificar origen/referer
		validOrigin := false
		if strings.Contains(referer, trustedOrigin) || strings.Contains(origin, trustedOrigin) {
			validOrigin = true
		}
		
		// Si no viene del origen confiable, rechazar
		if !validOrigin {
			log.Printf("🚫 Blocked invalid origin. Origin: %s, Referer: %s", origin, referer)
			c.JSON(http.StatusForbidden, APIResponse{
				Success: false,
				Message: "Acceso no autorizado - Origen inválido",
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
			log.Printf("🚫 IP not whitelisted: %s", clientIP)
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

// Middleware para limitar conexiones concurrentes MÁS ESTRICTO
func ConcurrentConnectionsMiddleware(maxConns int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		
		connMutex.Lock()
		currentConns := activeConns[ip]
		if currentConns >= maxConns {
			connMutex.Unlock()
			log.Printf("🔗 Too many concurrent connections from IP: %s (%d/%d)", ip, currentConns, maxConns)
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

// Middleware de timeout simplificado
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Crear un contexto con timeout
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()
		
		// Reemplazar el contexto de la request
		c.Request = c.Request.WithContext(ctx)
		
		// Canal para verificar si el handler terminó
		finished := make(chan bool, 1)
		
		go func() {
			c.Next()
			finished <- true
		}()
		
		select {
		case <-finished:
			// Handler terminó normalmente
			return
		case <-ctx.Done():
			// Timeout alcanzado
			log.Printf("⏱️ Request timeout for IP: %s", c.ClientIP())
			c.JSON(http.StatusRequestTimeout, APIResponse{
				Success: false,
				Message: "Request timeout",
				Data:    nil,
			})
			c.Abort()
			return
		}
	}
}

// Validación adicional para queries SQL MÁS ESTRICTA
func validateSQLQuery(query string) error {
	// Limpiar la query
	originalQuery := query
	query = strings.TrimSpace(strings.ToUpper(query))
	
	// Longitud máxima
	if len(query) > 1000 {  // Más estricto: 1000 caracteres
		return fmt.Errorf("query demasiado larga (%d caracteres, máximo 1000)", len(originalQuery))
	}
	
	// Prevenir múltiples statements
	if strings.Contains(query, ";") && !strings.HasSuffix(query, ";") {
		return fmt.Errorf("múltiples statements no permitidos")
	}
	
	// Palabras prohibidas MÁS EXTENSAS
	dangerous := []string{
		"DROP", "DELETE", "TRUNCATE", "SHUTDOWN", "PRAGMA", "ATTACH", "DETACH",
		"VACUUM", "REINDEX", "EXEC", "EXECUTE", "UNION", "SCRIPT", "--", "/*",
		"XP_", "SP_", "INFORMATION_SCHEMA", "SYSOBJECTS", "SYSCOLUMNS",
	}
	
	for _, word := range dangerous {
		if strings.Contains(query, word) {
			log.Printf("🛡️ SQL injection attempt blocked: %s", word)
			return fmt.Errorf("comando no permitido: %s", word)
		}
	}
	
	return nil
}

// Validar nombre de base de datos
func validateDatabaseName(name string) error {
	if len(name) == 0 || len(name) > 30 {  // Más estricto: 30 caracteres
		return fmt.Errorf("nombre de base de datos debe tener entre 1 y 30 caracteres")
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
	// Configuración de seguridad MÁS ESTRICTA
	config := SecurityConfig{
		MaxRequestsPerMin:   getEnvIntOrDefault("MAX_REQUESTS_PER_MIN", 30),   // Más estricto: 30/min
		MaxConcurrentConns:  getEnvIntOrDefault("MAX_CONCURRENT_CONNS", 3),    // Más estricto: 3 conexiones
		EnableIPWhitelist:   getEnvBoolOrDefault("ENABLE_IP_WHITELIST", false),
		AllowedIPs:          getEnvArrayOrDefault("ALLOWED_IPS", []string{}),
		RequestTimeout:      time.Duration(getEnvIntOrDefault("REQUEST_TIMEOUT_SECONDS", 15)) * time.Second, // Más rápido
		MaxQueryLength:      getEnvIntOrDefault("MAX_QUERY_LENGTH", 1000),     // Más corto
		TrustedOrigin:       getEnvOrDefault("TRUSTED_ORIGIN", "frontcompiladores.duckdns.org"),
	}
	
	log.Printf("🛡️  Protección backend ESTRICTA activada")
	log.Printf("⚡ Rate limit: %d requests/min", config.MaxRequestsPerMin)
	log.Printf("🔗 Conexiones concurrentes max: %d", config.MaxConcurrentConns)
	log.Printf("🌐 Origen confiable: %s", config.TrustedOrigin)
	log.Printf("⏱️ Timeout: %v", config.RequestTimeout)
	
	// Inicializar la base de datos
	err := InitDB()
	if err != nil {
		log.Fatal("Error al inicializar la base de datos:", err)
	}
	defer CloseDB()
	
	// Configurar Gin en modo release
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	
	// Middleware de seguridad global MÁS ESTRICTO
	r.Use(TimeoutMiddleware(config.RequestTimeout))
	r.Use(InputValidationMiddleware())
	r.Use(RateLimitMiddleware(config.MaxRequestsPerMin))
	r.Use(ConcurrentConnectionsMiddleware(config.MaxConcurrentConns))
	r.Use(TrustedOriginMiddleware(config.TrustedOrigin))  // ESTE es clave para bloquear orígenes
	
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
	
	// Health check SIN protecciones para permitir monitoreo
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
	
	log.Printf("🚀 Servidor ULTRA-SEGURO iniciado en puerto %s", port)
	log.Printf("🌐 CORS configurado para: https://frontcompiladores.duckdns.org")
	log.Printf("💡 Health check disponible en: /health")
	log.Fatal(http.ListenAndServe(":"+port, r))
}