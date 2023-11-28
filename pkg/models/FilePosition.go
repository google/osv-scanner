package models

type FilePosition struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}
