 package main

import (
	"fmt"
	"regexp"
	"strings"
)

// AnalyzeSyntactic realiza el análisis sintáctico de las declaraciones SQL
func AnalyzeSyntactic(requests LexicalRequest) SyntacticResult {
	var errors []string
	var parseTree strings.Builder
	var commandTypes []string
	
	if requests.CreateDB != "" {
		if err := validateCreateDatabase(requests.CreateDB); err != nil {
			errors = append(errors, fmt.Sprintf("CREATE DATABASE: %s", err.Error()))
		} else {
			commandTypes = append(commandTypes, "CREATE_DATABASE")
			parseTree.WriteString("CREATE DATABASE -> VALID\n")
		}
	}
	
	if requests.UseDB != "" {
		if err := validateUseDatabase(requests.UseDB); err != nil {
			errors = append(errors, fmt.Sprintf("USE DATABASE: %s", err.Error()))
		} else {
			commandTypes = append(commandTypes, "USE_DATABASE")
			parseTree.WriteString("USE DATABASE -> VALID\n")
		}
	}
	
	if requests.CreateTable != "" {
		if err := validateCreateTable(requests.CreateTable); err != nil {
			errors = append(errors, fmt.Sprintf("CREATE TABLE: %s", err.Error()))
		} else {
			commandTypes = append(commandTypes, "CREATE_TABLE")
			parseTree.WriteString("CREATE TABLE -> VALID\n")
		}
	}
	
	if requests.InsertData != "" {
		if err := validateInsert(requests.InsertData); err != nil {
			errors = append(errors, fmt.Sprintf("INSERT: %s", err.Error()))
		} else {
			commandTypes = append(commandTypes, "INSERT")
			parseTree.WriteString("INSERT -> VALID\n")
		}
	}
	
	if requests.ModifyData != "" {
		if err := validateModify(requests.ModifyData); err != nil {
			errors = append(errors, fmt.Sprintf("MODIFY: %s", err.Error()))
		} else {
			commandTypes = append(commandTypes, "UPDATE_DELETE")
			parseTree.WriteString("UPDATE/DELETE -> VALID\n")
		}
	}
	
	if requests.DeleteDB != "" {
		if err := validateDropDatabase(requests.DeleteDB); err != nil {
			errors = append(errors, fmt.Sprintf("DROP DATABASE: %s", err.Error()))
		} else {
			commandTypes = append(commandTypes, "DROP_DATABASE")
			parseTree.WriteString("DROP DATABASE -> VALID\n")
		}
	}
	
	return SyntacticResult{
		Valid:       len(errors) == 0,
		Errors:      errors,
		ParseTree:   parseTree.String(),
		CommandType: strings.Join(commandTypes, ", "),
	}
}

// validateCreateDatabase valida la sintaxis de CREATE DATABASE
func validateCreateDatabase(statement string) error {
	pattern := `^\s*CREATE\s+DATABASE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*$`
	if !regexp.MustCompile(`(?i)` + pattern).MatchString(statement) {
		return fmt.Errorf("sintaxis incorrecta. Formato esperado: CREATE DATABASE nombre_bd")
	}
	return nil
}

// validateUseDatabase valida la sintaxis de USE DATABASE
func validateUseDatabase(statement string) error {
	pattern := `^\s*USE\s+DATABASE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*$`
	if !regexp.MustCompile(`(?i)` + pattern).MatchString(statement) {
		return fmt.Errorf("sintaxis incorrecta. Formato esperado: USE DATABASE nombre_bd")
	}
	return nil
}

// validateCreateTable valida la sintaxis de CREATE TABLE
func validateCreateTable(statement string) error {
	pattern := `^\s*CREATE\s+TABLE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*)\)\s*$`
	if !regexp.MustCompile(`(?i)` + pattern).MatchString(statement) {
		return fmt.Errorf("sintaxis incorrecta. Formato esperado: CREATE TABLE nombre_tabla (col1 tipo1, col2 tipo2)")
	}
	return nil
}

// validateInsert valida la sintaxis de INSERT
func validateInsert(statement string) error {
	pattern := `^\s*INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(\([^)]*\))?\s*VALUES\s*\(.*\)\s*$`
	if !regexp.MustCompile(`(?i)` + pattern).MatchString(statement) {
		return fmt.Errorf("sintaxis incorrecta. Formato esperado: INSERT INTO tabla (cols) VALUES (vals)")
	}
	return nil
}

// validateModify valida la sintaxis de UPDATE/DELETE
func validateModify(statement string) error {
	// Validación para UPDATE
	updatePattern := `^\s*UPDATE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+SET\s+.+\s+WHERE\s+.+$`
	if regexp.MustCompile(`(?i)` + updatePattern).MatchString(statement) {
		return nil
	}
	
	// Validación para DELETE
	deletePattern := `^\s*DELETE\s+FROM\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+WHERE\s+.+$`
	if regexp.MustCompile(`(?i)` + deletePattern).MatchString(statement) {
		return nil
	}
	
	return fmt.Errorf("sintaxis incorrecta. Formato esperado: UPDATE tabla SET col=val WHERE condicion o DELETE FROM tabla WHERE condicion")
}

// validateDropDatabase valida la sintaxis de DROP DATABASE
func validateDropDatabase(statement string) error {
	pattern := `^\s*DROP\s+DATABASE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*$`
	if !regexp.MustCompile(`(?i)` + pattern).MatchString(statement) {
		return fmt.Errorf("sintaxis incorrecta. Formato esperado: DROP DATABASE nombre_bd")
	}
	return nil
}