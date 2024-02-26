package models

import (
	"encoding/json"
	"strings"
)

type PackageDetails struct {
	Name      string
	Version   string
	Ecosystem string
	Locations []PackageLocations
}

type PackageLocation struct {
	Filename    string `json:"file_name"`
	LineStart   int    `json:"line_start"`
	LineEnd     int    `json:"line_end"`
	ColumnStart int    `json:"column_start"`
	ColumnEnd   int    `json:"column_end"`
}

type PackageLocations struct {
	Block     *PackageLocation `json:"block"`
	Namespace *PackageLocation `json:"namespace,omitempty"`
	Name      *PackageLocation `json:"name,omitempty"`
	Version   *PackageLocation `json:"version,omitempty"`
}

func (location PackageLocations) EncodeToJSONString() (string, error) {
	buffer := strings.Builder{}
	encoder := json.NewEncoder(&buffer)

	err := encoder.Encode(location)
	if err != nil {
		return "", err
	}

	return buffer.String(), nil
}
