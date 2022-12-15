package output

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"

	"github.com/google/osv-scanner/pkg/models"
)

// PrintJSONResults writes results to the provided writer in JSON format
func PrintJSONResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer, savePath string) (err error) {
	var buf = new(bytes.Buffer)

	encoder := json.NewEncoder(buf)
	encoder.SetIndent("", "  ")

	err = encoder.Encode(vulnResult)
	if err != nil {
		return
	}

	if savePath != "" {
		err = os.WriteFile(savePath, buf.Bytes(), fs.ModePerm)
		if err != nil {
			return
		}
	}

	_, err = outputWriter.Write(buf.Bytes())

	return
}
