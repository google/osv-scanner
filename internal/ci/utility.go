package ci

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/osv-scanner/pkg/models"
)

func LoadVulnResults(path string) (models.VulnerabilityResults, error) {
	file, err := os.Open(path)
	if err != nil {
		return models.VulnerabilityResults{}, fmt.Errorf("failed to load '%s'", path)
	}
	var value models.VulnerabilityResults
	err = json.NewDecoder(file).Decode(&value)
	if err != nil {
		return models.VulnerabilityResults{}, fmt.Errorf("failed to parse '%s'", path)
	}

	return value, nil
}
