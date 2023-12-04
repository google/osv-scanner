package reporter

import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/google/osv-scanner/pkg/models"
	sbomproto "github.com/google/osv-scanner/pkg/reporter/sbom"
	"github.com/package-url/packageurl-go"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type DatadogSbomReporter struct {
	client          *http.Client
	hasPrintedError bool
	stdout          io.Writer
	stderr          io.Writer
}

const (
	EndpointPath = "/api/v2/sbom"
)

var (
	apiUrlPerSite = map[string]string{
		"us1": "https://event-platform-intake.datadoghq.com",
		"eu1": "https://event-platform-intake.datadoghq.eu",
		"us3": "https://event-platform-intake.us3.datadoghq.com",
		"us5": "https://event-platform-intake.us5.datadoghq.com",
		"ap1": "https://event-platform-intake.ap1.datadoghq.com",
	}
)

func NewDatadogSbomReporter(stdout io.Writer, stderr io.Writer) *DatadogSbomReporter {
	return &DatadogSbomReporter{
		stdout:          stdout,
		stderr:          stderr,
		hasPrintedError: false,
		client:          &http.Client{},
	}
}

func (r *DatadogSbomReporter) PrintError(msg string) {
	_, _ = fmt.Fprint(r.stderr, msg)
	r.hasPrintedError = true
}

func (r *DatadogSbomReporter) HasPrintedError() bool {
	return r.hasPrintedError
}

func (r *DatadogSbomReporter) PrintText(msg string) {
	_, _ = fmt.Fprint(r.stderr, msg)
}

func (r *DatadogSbomReporter) PrintResult(vulnResults *models.VulnerabilityResults) error {
	var baseURL string

	site := os.Getenv("DD_SITE")
	if site != "" {
		baseURL = apiUrlPerSite[site]
	}

	if os.Getenv("DD_API_URL") != "" {
		baseURL = os.Getenv("DD_API_URL")
	}

	if baseURL == "" {
		log.Println("No DD_SITE or DD_API_URL defined, using us1 site as default")
		baseURL = apiUrlPerSite["us1"]
	}

	apiURL := baseURL + EndpointPath

	apiKey := os.Getenv("DD_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("DD_API_KEY is not set")
	}

	bs, err := toRequestBody(vulnResults)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(bs))
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

func toRequestBody(results *models.VulnerabilityResults) ([]byte, error) {
	source := "CI"

	bom := toBom(results)

	now := timestamppb.Now()

	repositoryURL, err := getRepositoryURL()
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

	bs, err := proto.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return bs, nil
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
			packageURLInstance := getPackageURL(packageInfo.Package)
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

			if packageInfo.Package.Start.Line != 0 {
				lineStart := strconv.Itoa(packageInfo.Package.Start.Line)
				lineEnd := strconv.Itoa(packageInfo.Package.End.Line)
				columnStart := strconv.Itoa(packageInfo.Package.Start.Column)
				columnEnd := strconv.Itoa(packageInfo.Package.End.Column)
				component.Properties = append(component.Properties,
					&sbomproto.Property{
						Name:  "location_line_start",
						Value: &lineStart,
					},
					&sbomproto.Property{
						Name:  "location_line_end",
						Value: &lineEnd,
					},
					&sbomproto.Property{
						Name:  "location_column_start",
						Value: &columnStart,
					},
					&sbomproto.Property{
						Name:  "location_column_end",
						Value: &columnEnd,
					})
			}

			bom.Components = append(bom.Components, &component)
		}
	}

	return bom
}

func getPackageURL(packageInfo models.PackageInfo) *packageurl.PackageURL {
	var purlType string
	var namespace string
	name := packageInfo.Name
	version := packageInfo.Version

	switch packageInfo.Ecosystem {
	case string(models.EcosystemMaven):
		nameParts := strings.Split(packageInfo.Name, ":")
		if len(nameParts) != 2 {
			log.Printf("invalid maven package_name=%s", packageInfo.Name)
			return nil
		}
		purlType = packageurl.TypeMaven
		namespace = nameParts[0]
		name = nameParts[1]
	case string(models.EcosystemGo):
		nameParts := strings.Split(packageInfo.Name, "/")
		if len(nameParts) < 2 {
			log.Printf("invalid golang package_name=%s", packageInfo.Name)
			return nil
		}
		purlType = packageurl.TypeGolang
		namespace = strings.Join(nameParts[:len(nameParts)-1], "/")
		name = nameParts[len(nameParts)-1]
	case string(models.EcosystemPackagist):
		nameParts := strings.Split(packageInfo.Name, "/")
		if len(nameParts) != 2 {
			log.Printf("invalid packagist package_name=%s", packageInfo.Name)
			return nil
		}
		purlType = packageurl.TypeComposer
		namespace = nameParts[0]
		name = nameParts[1]
	case string(models.EcosystemPyPI):
		purlType = packageurl.TypePyPi
	case string(models.EcosystemRubyGems):
		purlType = packageurl.TypeGem
	case string(models.EcosystemNuGet):
		purlType = packageurl.TypeNuget
	case string(models.EcosystemNPM):
		purlType = packageurl.TypeNPM
	default:
		return nil
	}

	return packageurl.NewPackageURL(purlType, namespace, name, version, nil, "")
}

func getRepositoryURL() (string, error) {
	githubRepository := os.Getenv("GITHUB_REPOSITORY")
	if githubRepository != "" {
		return fmt.Sprintf("git@github.com:%s.git", githubRepository), nil
	}

	repositoryUrl := os.Getenv("REPOSITORY_URL")
	if repositoryUrl != "" {
		return repositoryUrl, nil
	}

	return "", fmt.Errorf("REPOSITORY_URL is not set")
}
