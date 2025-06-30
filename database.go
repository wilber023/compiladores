package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

var (
	db           *sql.DB
	currentDB    string
	databasesDir = "./databases" // Directorio donde se guardarán las bases de datos
)

// Configuración de la base de datos - Modifica estos valores según tus necesidades
type DatabaseConfig struct {
	Driver      string
	DatabaseDir string
	Extension   string
}

func GetDatabaseConfig() DatabaseConfig {
	return DatabaseConfig{
		Driver:      "sqlite3",
		DatabaseDir: "./databases",
		Extension:   ".db",
	}
}

// InitDB inicializa la conexión a la base de datos
func InitDB() error {
	config := GetDatabaseConfig()
	
	// Crear directorio para bases de datos si no existe
	err := os.MkdirAll(config.DatabaseDir, 0755)
	if err != nil {
		return fmt.Errorf("error al crear directorio de bases de datos: %v", err)
	}

	databasesDir = config.DatabaseDir
	return nil
}

// CreateDatabase crea una nueva base de datos
 func CreateDatabase(name string) error {
    config := GetDatabaseConfig()
    dbPath := filepath.Join(config.DatabaseDir, name+config.Extension)

    fmt.Printf("[CreateDatabase] Intentando crear BD en ruta: %s\n", dbPath)

    // Verificar que el directorio existe
    dir := filepath.Dir(dbPath)
    if _, err := os.Stat(dir); os.IsNotExist(err) {
        fmt.Printf("[CreateDatabase] Directorio no existe, intentando crear: %s\n", dir)
        err := os.MkdirAll(dir, 0755)
        if err != nil {
            return fmt.Errorf("error al crear directorio para BD: %v", err)
        }
    }

    if _, err := os.Stat(dbPath); err == nil {
        return fmt.Errorf("la base de datos '%s' ya existe", name)
    }

    database, err := sql.Open(config.Driver, dbPath)
    if err != nil {
        return fmt.Errorf("error al crear la base de datos: %v", err)
    }
    defer database.Close()

    err = database.Ping()
    if err != nil {
        return fmt.Errorf("error al conectar con la base de datos: %v", err)
    }

    fmt.Printf("[CreateDatabase] Base de datos creada con éxito\n")
    return nil
}


// UseDatabase cambia a una base de datos específica
func UseDatabase(name string) error {
	config := GetDatabaseConfig()
	dbPath := filepath.Join(config.DatabaseDir, name+config.Extension)
	
	// Verificar si la base de datos existe
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("la base de datos '%s' no existe", name)
	}

	// Cerrar conexión anterior si existe
	if db != nil {
		db.Close()
	}

	// Abrir nueva conexión
	database, err := sql.Open(config.Driver, dbPath)
	if err != nil {
		return fmt.Errorf("error al conectar con la base de datos: %v", err)
	}

	err = database.Ping()
	if err != nil {
		return fmt.Errorf("error al verificar conexión: %v", err)
	}

	db = database
	currentDB = name
	return nil
}

// DeleteDatabase elimina una base de datos
func DeleteDatabase(name string) error {
	config := GetDatabaseConfig()
	dbPath := filepath.Join(config.DatabaseDir, name+config.Extension)
	
	// Cerrar conexión si es la base de datos actual
	if currentDB == name && db != nil {
		db.Close()
		db = nil
		currentDB = ""
	}

	// Eliminar archivo
	err := os.Remove(dbPath)
	if err != nil {
		return fmt.Errorf("error al eliminar la base de datos: %v", err)
	}

	return nil
}

// ExecuteQuery ejecuta una consulta SQL
func ExecuteQuery(query string) error {
	if db == nil {
		return fmt.Errorf("no hay ninguna base de datos seleccionada")
	}

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("error al ejecutar consulta: %v", err)
	}

	return nil
}

// GetDatabaseInfo obtiene información de la base de datos actual
func GetDatabaseInfo() (*DatabaseInfo, error) {
	if db == nil || currentDB == "" {
		return nil, fmt.Errorf("no hay ninguna base de datos seleccionada")
	}

	info := &DatabaseInfo{
		Name:   currentDB,
		Tables: []TableInfo{},
	}

	// Obtener lista de tablas
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return nil, fmt.Errorf("error al obtener tablas: %v", err)
	}
	defer rows.Close()

	var tableNames []string
	for rows.Next() {
		var tableName string
		err := rows.Scan(&tableName)
		if err != nil {
			continue
		}
		tableNames = append(tableNames, tableName)
	}

	// Obtener información de cada tabla
	for _, tableName := range tableNames {
		tableInfo, err := getTableInfo(tableName)
		if err != nil {
			continue
		}
		info.Tables = append(info.Tables, *tableInfo)
	}

	return info, nil
}

func getTableInfo(tableName string) (*TableInfo, error) {
	table := &TableInfo{
		Name:    tableName,
		Columns: []ColumnInfo{},
		Data:    []map[string]interface{}{},
	}

	// Obtener información de columnas
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var defaultValue sql.NullString

		err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
		if err != nil {
			continue
		}

		table.Columns = append(table.Columns, ColumnInfo{
			Name: name,
			Type: dataType,
		})
	}

	// Obtener datos de la tabla
	dataRows, err := db.Query(fmt.Sprintf("SELECT * FROM %s LIMIT 100", tableName))
	if err != nil {
		return table, nil // Retornar tabla sin datos en caso de error
	}
	defer dataRows.Close()

	columns, err := dataRows.Columns()
	if err != nil {
		return table, nil
	}

	for dataRows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		err := dataRows.Scan(valuePtrs...)
		if err != nil {
			continue
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if val != nil {
				switch v := val.(type) {
				case []byte:
					row[col] = string(v)
				default:
					row[col] = v
				}
			} else {
				row[col] = nil
			}
		}
		table.Data = append(table.Data, row)
	}

	return table, nil
}

// CloseDB cierra la conexión a la base de datos
func CloseDB() {
	if db != nil {
		db.Close()
	}
}