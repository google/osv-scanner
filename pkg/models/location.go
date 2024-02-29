package models

import (
	"encoding/json"
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
	Block     PackageLocation  `json:"block"`
	Namespace *PackageLocation `json:"namespace,omitempty"`
	Name      *PackageLocation `json:"name,omitempty"`
	Version   *PackageLocation `json:"version,omitempty"`
}

func (location PackageLocations) MarshalToJSONString() (string, error) {
	str, err := json.Marshal(location)
	if err != nil {
		return "", err
	}

	return string(str), nil
}
