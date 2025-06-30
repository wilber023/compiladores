package main

// Request structures
type LexicalRequest struct {
	CreateDB    string `json:"createDB"`
	UseDB       string `json:"useDB"`
	CreateTable string `json:"createTable"`
	InsertData  string `json:"insertData"`
	ModifyData  string `json:"modifyData"`
	DeleteDB    string `json:"deleteDB"`
}

type DatabaseRequest struct {
	Database string `json:"database"`
}

type QueryRequest struct {
	Query string `json:"query"`
}

// Response structures
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type Token struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

type StatementAnalysis struct {
	Statement string  `json:"statement"`
	Tokens    []Token `json:"tokens"`
	Keywords  []Token `json:"keywords"`
}

type DatabaseInfo struct {
	Name   string      `json:"name"`
	Tables []TableInfo `json:"tables"`
}

type TableInfo struct {
	Name    string                   `json:"name"`
	Columns []ColumnInfo             `json:"columns"`
	Data    []map[string]interface{} `json:"data"`
}

type ColumnInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type SyntacticResult struct {
	Valid       bool     `json:"valid"`
	Errors      []string `json:"errors"`
	ParseTree   string   `json:"parseTree"`
	CommandType string   `json:"commandType"`
}