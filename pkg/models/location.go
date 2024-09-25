package models

import (
	"encoding/json"
	"strconv"
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
	Block     PackageLocation  `json:"block"`
	Namespace *PackageLocation `json:"namespace,omitempty"`
	Name      *PackageLocation `json:"name,omitempty"`
	Version   *PackageLocation `json:"version,omitempty"`
}

func (location PackageLocation) IsValid() bool {
	return len(location.Filename) > 0 && location.LineStart > 0 && location.LineEnd > 0
}

func (location PackageLocations) Clean() *PackageLocations {
	if !location.Block.IsValid() {
		return nil
	}

	if location.Name != nil && !location.Name.IsValid() {
		location.Name = nil
	}
	if location.Namespace != nil && !location.Namespace.IsValid() {
		location.Namespace = nil
	}
	if location.Version != nil && !location.Version.IsValid() {
		location.Version = nil
	}

	return &location
}

func (location PackageLocations) MarshalToJSONString() (string, error) {
	str, err := json.Marshal(location)
	if err != nil {
		return "", err
	}

	return string(str), nil
}

func (location PackageLocation) Hash() string {
	return strings.Join([]string{
		location.Filename,
		strconv.Itoa(location.LineStart),
		strconv.Itoa(location.LineEnd),
		strconv.Itoa(location.ColumnStart),
		strconv.Itoa(location.ColumnEnd),
	}, "#")
}
