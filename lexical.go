package main

import (
	"regexp"
	"strings"
)

// Palabras reservadas de SQL
var sqlKeywords = map[string]bool{
	"CREATE":    true,
	"DATABASE":  true,
	"TABLE":     true,
	"USE":       true,
	"INSERT":    true,
	"INTO":      true,
	"VALUES":    true,
	"UPDATE":    true,
	"SET":       true,
	"DELETE":    true,
	"FROM":      true,
	"WHERE":     true,
	"SELECT":    true,
	"DROP":      true,
	"ALTER":     true,
	"PRIMARY":   true,
	"KEY":       true,
	"FOREIGN":   true,
	"NOT":       true,
	"NULL":      true,
	"UNIQUE":    true,
	"INDEX":     true,
	"AND":       true,
	"OR":        true,
	"IN":        true,
	"LIKE":      true,
	"BETWEEN":   true,
	"ORDER":     true,
	"BY":        true,
	"GROUP":     true,
	"HAVING":    true,
	"JOIN":      true,
	"INNER":     true,
	"LEFT":      true,
	"RIGHT":     true,
	"OUTER":     true,
	"ON":        true,
	"AS":        true,
	"DISTINCT":  true,
	"COUNT":     true,
	"SUM":       true,
	"AVG":       true,
	"MAX":       true,
	"MIN":       true,
	"INTEGER":   true,
	"TEXT":      true,
	"REAL":      true,
	"BLOB":      true,
	"NUMERIC":   true,
	"VARCHAR":   true,
	"CHAR":      true,
	"BOOLEAN":   true,
	"DATE":      true,
	"TIME":      true,
	"DATETIME":  true,
	"TIMESTAMP": true,
}

// Tipos de tokens
const (
	KEYWORD    = "KEYWORD"
	IDENTIFIER = "IDENTIFIER"
	NUMBER     = "NUMBER"
	STRING     = "STRING"
	OPERATOR   = "OPERATOR"
	DELIMITER  = "DELIMITER"
	SYMBOL     = "SYMBOL"
	UNKNOWN    = "UNKNOWN"
)

// Expresiones regulares para diferentes tipos de tokens
var (
	numberRegex     = regexp.MustCompile(`^\d+(\.\d+)?$`)
	stringRegex     = regexp.MustCompile(`^'([^']*)'$`)
	identifierRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	operatorRegex   = regexp.MustCompile(`^(=|<>|!=|<=|>=|<|>|\+|-|\*|/)$`)
	delimiterRegex  = regexp.MustCompile(`^[(),;]$`)
)

// AnalyzeLexical realiza el análisis léxico de una declaración SQL
func AnalyzeLexical(statement string) StatementAnalysis {
	if strings.TrimSpace(statement) == "" {
		return StatementAnalysis{
			Statement: statement,
			Tokens:    []Token{},
			Keywords:  []Token{},
		}
	}

	tokens := tokenize(statement)
	keywords := extractKeywords(tokens)

	return StatementAnalysis{
		Statement: statement,
		Tokens:    tokens,
		Keywords:  keywords,
	}
}

// tokenize divide la declaración en tokens
func tokenize(statement string) []Token {
	var tokens []Token
	
	// Limpiar y dividir por espacios, pero mantener las comillas
	statement = strings.TrimSpace(statement)
	
	var currentToken strings.Builder
	var inString bool
	var stringChar rune
	
	for i, char := range statement {
		switch {
		case char == '\'' || char == '"':
			if !inString {
				// Inicio de string
				if currentToken.Len() > 0 {
					tokens = append(tokens, createToken(currentToken.String()))
					currentToken.Reset()
				}
				inString = true
				stringChar = char
				currentToken.WriteRune(char)
			} else if char == stringChar {
				// Final de string
				currentToken.WriteRune(char)
				tokens = append(tokens, createToken(currentToken.String()))
				currentToken.Reset()
				inString = false
			} else {
				currentToken.WriteRune(char)
			}
		case inString:
			currentToken.WriteRune(char)
		case char == ' ' || char == '\t' || char == '\n' || char == '\r':
			if currentToken.Len() > 0 {
				tokens = append(tokens, createToken(currentToken.String()))
				currentToken.Reset()
			}
		case char == '(' || char == ')' || char == ',' || char == ';':
			if currentToken.Len() > 0 {
				tokens = append(tokens, createToken(currentToken.String()))
				currentToken.Reset()
			}
			tokens = append(tokens, createToken(string(char)))
		case char == '=' || char == '<' || char == '>' || char == '!' || 
			 char == '+' || char == '-' || char == '*' || char == '/':
			if currentToken.Len() > 0 {
				tokens = append(tokens, createToken(currentToken.String()))
				currentToken.Reset()
			}
			
			// Manejar operadores de dos caracteres
			if i+1 < len(statement) {
				nextChar := rune(statement[i+1])
				twoCharOp := string(char) + string(nextChar)
				if operatorRegex.MatchString(twoCharOp) {
					tokens = append(tokens, createToken(twoCharOp))
					// Saltar el siguiente carácter
					continue
				}
			}
			tokens = append(tokens, createToken(string(char)))
		default:
			currentToken.WriteRune(char)
		}
	}
	
	if currentToken.Len() > 0 {
		tokens = append(tokens, createToken(currentToken.String()))
	}
	
	return tokens
}

// createToken crea un token identificando su tipo
func createToken(value string) Token {
	value = strings.TrimSpace(value)
	if value == "" {
		return Token{Value: value, Type: UNKNOWN}
	}
	
	upperValue := strings.ToUpper(value)
	
	// Verificar si es palabra reservada
	if sqlKeywords[upperValue] {
		return Token{Value: value, Type: KEYWORD}
	}
	
	// Verificar si es string literal
	if stringRegex.MatchString(value) {
		return Token{Value: value, Type: STRING}
	}
	
	// Verificar si es número
	if numberRegex.MatchString(value) {
		return Token{Value: value, Type: NUMBER}
	}
	
	// Verificar si es operador
	if operatorRegex.MatchString(value) {
		return Token{Value: value, Type: OPERATOR}
	}
	
	// Verificar si es delimitador
	if delimiterRegex.MatchString(value) {
		return Token{Value: value, Type: DELIMITER}
	}
	
	// Verificar si es identificador válido
	if identifierRegex.MatchString(value) {
		return Token{Value: value, Type: IDENTIFIER}
	}
	
	// Si no coincide con ningún patrón, es símbolo o desconocido
	return Token{Value: value, Type: SYMBOL}
}

// extractKeywords extrae solo las palabras reservadas de los tokens
func extractKeywords(tokens []Token) []Token {
	var keywords []Token
	for _, token := range tokens {
		if token.Type == KEYWORD {
			keywords = append(keywords, token)
		}
	}
	return keywords
}

// AnalyzeLexicalBatch analiza múltiples declaraciones
func AnalyzeLexicalBatch(requests LexicalRequest) []StatementAnalysis {
	var results []StatementAnalysis
	
	statements := []string{
		requests.CreateDB,
		requests.UseDB,
		requests.CreateTable,
		requests.InsertData,
		requests.ModifyData,
		requests.DeleteDB,
	}
	
	for _, statement := range statements {
		if strings.TrimSpace(statement) != "" {
			analysis := AnalyzeLexical(statement)
			results = append(results, analysis)
		}
	}
	
	return results
}