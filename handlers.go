package main

import (
	"net/http"
	"regexp"
	"strings"
	"fmt"
	"github.com/gin-gonic/gin"
)

// LexicalAnalysisHandler maneja el análisis léxico
func LexicalAnalysisHandler(c *gin.Context) {
	var req LexicalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos",
			Data:    nil,
		})
		return
	}

	results := AnalyzeLexicalBatch(req)

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Análisis léxico completado exitosamente",
		Data:    results,
	})
}

// SyntacticAnalysisHandler maneja el análisis sintáctico y ejecuta comandos
func SyntacticAnalysisHandler(c *gin.Context) {
	var req LexicalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos",
			Data:    nil,
		})
		return
	}

	// Realizar análisis sintáctico
	results := AnalyzeSyntactic(req)

	// Si hay errores sintácticos, no ejecutar comandos
	if !results.Valid {
		c.JSON(http.StatusOK, APIResponse{
			Success: false,
			Message: "Errores sintácticos encontrados",
			Data:    results,
		})
		return
	}

	// Ejecutar comandos si la sintaxis es válida
	executionResults := executeCommandsSequentially(req)

	// Combinar resultados sintácticos con resultados de ejecución
	combinedResults := map[string]interface{}{
		"syntactic": results,
		"execution": executionResults,
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Análisis sintáctico completado y comandos ejecutados",
		Data:    combinedResults,
	})
}

// CreateDatabaseHandler crea una nueva base de datos
 func CreateDatabaseHandler(c *gin.Context) {
    var req DatabaseRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, APIResponse{
            Success: false,
            Message: "Datos de entrada inválidos",
            Data:    nil,
        })
        return
    }

    err := CreateDatabase(req.Database)
    if err != nil {
        fmt.Printf("[CreateDatabaseHandler] Error: %v\n", err)
        c.JSON(http.StatusInternalServerError, APIResponse{
            Success: false,
            Message: err.Error(),
            Data:    nil,
        })
        return
    }

    c.JSON(http.StatusOK, APIResponse{
        Success: true,
        Message: "Base de datos creada exitosamente: " + req.Database,
        Data:    nil,
    })
}


// UseDatabaseHandler selecciona una base de datos
func UseDatabaseHandler(c *gin.Context) {
	var req DatabaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos",
			Data:    nil,
		})
		return
	}

	err := UseDatabase(req.Database)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Usando base de datos: " + req.Database,
		Data:    nil,
	})
}

// CreateTableHandler crea una nueva tabla
func CreateTableHandler(c *gin.Context) {
	var req QueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos",
			Data:    nil,
		})
		return
	}

	err := ExecuteQuery(req.Query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Tabla creada exitosamente",
		Data:    nil,
	})
}

// InsertDataHandler inserta datos en una tabla
func InsertDataHandler(c *gin.Context) {
	var req QueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos",
			Data:    nil,
		})
		return
	}

	err := ExecuteQuery(req.Query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Datos insertados exitosamente",
		Data:    nil,
	})
}

// ModifyDataHandler modifica datos (UPDATE/DELETE)
func ModifyDataHandler(c *gin.Context) {
	var req QueryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos",
			Data:    nil,
		})
		return
	}

	err := ExecuteQuery(req.Query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Datos modificados exitosamente",
		Data:    nil,
	})
}

// DeleteDatabaseHandler elimina una base de datos
func DeleteDatabaseHandler(c *gin.Context) {
	var req DatabaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Datos de entrada inválidos",
			Data:    nil,
		})
		return
	}

	err := DeleteDatabase(req.Database)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Base de datos eliminada exitosamente: " + req.Database,
		Data:    nil,
	})
}

// GetDatabaseInfoHandler obtiene información de la base de datos actual
func GetDatabaseInfoHandler(c *gin.Context) {
	info, err := GetDatabaseInfo()
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: err.Error(),
			Data:    nil,
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Información de base de datos obtenida exitosamente",
		Data:    info,
	})
}

// executeCommandsSequentially ejecuta los comandos en secuencia
func executeCommandsSequentially(req LexicalRequest) map[string]interface{} {
	results := make(map[string]interface{})

	// Crear base de datos
	if req.CreateDB != "" {
		dbName := extractDatabaseName(req.CreateDB)
		if dbName != "" {
			err := CreateDatabase(dbName)
			if err != nil {
				results["createDB"] = map[string]interface{}{
					"success": false,
					"message": err.Error(),
				}
			} else {
				results["createDB"] = map[string]interface{}{
					"success": true,
					"message": "Base de datos creada: " + dbName,
				}
			}
		}
	}

	// Usar base de datos
	if req.UseDB != "" {
		dbName := extractDatabaseName(req.UseDB)
		if dbName != "" {
			err := UseDatabase(dbName)
			if err != nil {
				results["useDB"] = map[string]interface{}{
					"success": false,
					"message": err.Error(),
				}
			} else {
				results["useDB"] = map[string]interface{}{
					"success": true,
					"message": "Usando base de datos: " + dbName,
				}
			}
		}
	}

	// Crear tabla
	if req.CreateTable != "" {
		err := ExecuteQuery(req.CreateTable)
		if err != nil {
			results["createTable"] = map[string]interface{}{
				"success": false,
				"message": err.Error(),
			}
		} else {
			results["createTable"] = map[string]interface{}{
				"success": true,
				"message": "Tabla creada exitosamente",
			}
		}
	}

	// Insertar datos
	if req.InsertData != "" {
		err := ExecuteQuery(req.InsertData)
		if err != nil {
			results["insertData"] = map[string]interface{}{
				"success": false,
				"message": err.Error(),
			}
		} else {
			results["insertData"] = map[string]interface{}{
				"success": true,
				"message": "Datos insertados exitosamente",
			}
		}
	}

	// Modificar datos
	if req.ModifyData != "" {
		err := ExecuteQuery(req.ModifyData)
		if err != nil {
			results["modifyData"] = map[string]interface{}{
				"success": false,
				"message": err.Error(),
			}
		} else {
			results["modifyData"] = map[string]interface{}{
				"success": true,
				"message": "Datos modificados exitosamente",
			}
		}
	}

	return results
}

// extractDatabaseName extrae el nombre de la base de datos de un comando
func extractDatabaseName(command string) string {
	// Usar expresión regular para extraer el nombre de la base de datos
	patterns := []string{
		`(?i)CREATE\s+DATABASE\s+([a-zA-Z_][a-zA-Z0-9_]*)`,
		`(?i)USE\s+([a-zA-Z_][a-zA-Z0-9_]*)`,
		`(?i)DROP\s+DATABASE\s+([a-zA-Z_][a-zA-Z0-9_]*)`,
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindStringSubmatch(command)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	// Fallback: dividir por espacios y tomar el último elemento
	words := strings.Fields(strings.TrimSpace(command))
	if len(words) > 0 {
		return words[len(words)-1]
	}

	return ""
}