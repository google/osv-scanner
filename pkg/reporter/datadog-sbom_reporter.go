package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter/purl"
	sbomproto "github.com/google/osv-scanner/pkg/reporter/sbom"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type DatadogSbomReporter struct {
	client          *http.Client
	hasPrintedError bool
	stdout          io.Writer
	stderr          io.Writer
	offline         bool
}

const (
	EndpointPath = "/api/v2/sbom"
)

var (
	apiURLPerSite = map[string]string{
		"us1": "https://event-platform-intake.datadoghq.com",
		"eu1": "https://event-platform-intake.datadoghq.eu",
		"us3": "https://event-platform-intake.us3.datadoghq.com",
		"us5": "https://event-platform-intake.us5.datadoghq.com",
		"ap1": "https://event-platform-intake.ap1.datadoghq.com",
	}
)

func NewDatadogSbomReporter(stdout io.Writer, stderr io.Writer, offline bool) *DatadogSbomReporter {
	return &DatadogSbomReporter{
		stdout:          stdout,
		stderr:          stderr,
		hasPrintedError: false,
		client:          &http.Client{},
		offline:         offline,
	}
}

func (r *DatadogSbomReporter) PrintError(msg string) {
	_, _ = fmt.Fprint(r.stderr, msg)
	r.hasPrintedError = true
}

func (r *DatadogSbomReporter) PrintErrorf(msg string, a ...any) {
	fmt.Fprintf(r.stderr, msg, a...)
	r.hasPrintedError = true
}

func (r *DatadogSbomReporter) HasPrintedError() bool {
	return r.hasPrintedError
}

func (r *DatadogSbomReporter) PrintText(msg string) {
	_, _ = fmt.Fprint(r.stderr, msg)
}

func (r *DatadogSbomReporter) PrintTextf(msg string, a ...any) {
	fmt.Fprintf(r.stderr, msg, a...)
}

func (r *DatadogSbomReporter) sendToDatadog(data []byte) error {
	var baseURL string

	site := os.Getenv("DD_SITE")
	if site != "" {
		baseURL = apiURLPerSite[site]
	}

	if os.Getenv("DD_API_URL") != "" {
		baseURL = os.Getenv("DD_API_URL")
	}

	if baseURL == "" {
		log.Println("No DD_SITE or DD_API_URL defined, using us1 site as default")
		baseURL = apiURLPerSite["us1"]
	}

	apiURL := baseURL + EndpointPath

	apiKey := os.Getenv("DD_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("DD_API_KEY is not set")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, apiURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("DD-API-KEY", apiKey)

	response, err := r.client.Do(req)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	err = response.Body.Close()
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("error sending request with status='%v' and body='%v'", response.Status, string(body))
	}

	log.Println("Successfully sent SBOM to Datadog")

	return nil
}

func (r *DatadogSbomReporter) PrintResult(vulnResults *models.VulnerabilityResults) error {
	bs, err := r.toRequestBody(vulnResults)
	if err != nil {
		return err
	}

	if !r.offline {
		return r.sendToDatadog(bs)
	}
	_, err = r.stdout.Write(bs)

	return err
}

func (r *DatadogSbomReporter) toRequestBody(results *models.VulnerabilityResults) ([]byte, error) {
	source := "CI"

	bom := toBom(results)

	now := timestamppb.Now()

	repositoryURL, err := r.getRepositoryURL()
	if err != nil {
		return nil, err
	}

	ddtags := readEnvironmentTags()

	payload := &sbomproto.SBOMPayload{
		Version: 1,
		Host:    "",
		Source:  &source,
		Entities: []*sbomproto.SBOMEntity{
			{
				Type:               sbomproto.SBOMSourceType_CI_PIPELINE,
				Id:                 repositoryURL,
				GeneratedAt:        now,
				GenerationDuration: durationpb.New(0),
				InUse:              true,
				Heartbeat:          false,
				Sbom: &sbomproto.SBOMEntity_Cyclonedx{
					Cyclonedx: bom,
				},
				Status: sbomproto.SBOMStatus_SUCCESS,
				DdTags: ddtags,
			},
		},
	}

	if !r.offline {
		return proto.Marshal(payload)
	}

	return json.Marshal(bom)
}

func readEnvironmentTags() []string {
	branchName := os.Getenv("GITHUB_REF_NAME")
	commitSha := os.Getenv("GITHUB_SHA")
	var ddtags []string
	if branchName != "" {
		ddtags = append(ddtags, fmt.Sprintf("git.branch:%s", branchName))
	}
	if commitSha != "" {
		ddtags = append(ddtags, fmt.Sprintf("git.commit.sha:%s", commitSha))
	}

	return ddtags
}

func toBom(results *models.VulnerabilityResults) *sbomproto.Bom {
	var version int32 = 1
	bom := &sbomproto.Bom{
		SpecVersion: "1.4",
		Version:     &version,
		Components:  []*sbomproto.Component{},
	}

	for _, result := range results.Results {
		filename := result.Source.Path
		for _, packageInfo := range result.Packages {
			packageURLInstance := purl.From(packageInfo.Package)
			if packageURLInstance == nil {
				continue
			}

			purlString := packageURLInstance.ToString()
			props := make([]*sbomproto.Property, 0)
			props = append(props, &sbomproto.Property{
				Name:  "location_file",
				Value: &filename,
			})

			component := sbomproto.Component{
				Type:       sbomproto.Classification_CLASSIFICATION_LIBRARY,
				Name:       packageInfo.Package.Name,
				Version:    packageInfo.Package.Version,
				BomRef:     &purlString,
				Purl:       &purlString,
				Properties: props,
			}

			if packageInfo.Package.Start != 0 {
				lineStart := strconv.Itoa(packageInfo.Package.Start)
				lineEnd := strconv.Itoa(packageInfo.Package.End)
				component.Properties = append(component.GetProperties(),
					&sbomproto.Property{
						Name:  "location_line_start",
						Value: &lineStart,
					},
					&sbomproto.Property{
						Name:  "location_line_end",
						Value: &lineEnd,
					})
			}

			bom.Components = append(bom.GetComponents(), &component)
		}
	}

	return bom
}

func (r *DatadogSbomReporter) getRepositoryURL() (string, error) {
	githubRepository := os.Getenv("GITHUB_REPOSITORY")
	if githubRepository != "" {
		return fmt.Sprintf("git@github.com:%s.git", githubRepository), nil
	}

	repositoryURL := os.Getenv("REPOSITORY_URL")
	if repositoryURL != "" {
		return repositoryURL, nil
	}

	if r.offline {
		return "offline-scan", nil
	}

	return "", fmt.Errorf("REPOSITORY_URL is not set")
}
