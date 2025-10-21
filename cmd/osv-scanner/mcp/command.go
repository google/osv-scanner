// Package mcp implements the `mcp` command for osv-scanner.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"net/http"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/urfave/cli/v3"
	"osv.dev/bindings/go/osvdev"
)

var vulnCacheMap = map[string]*osvschema.Vulnerability{}

func Command(_, _ io.Writer) *cli.Command {
	return &cli.Command{
		Name:        "experimental-mcp",
		Usage:       "Run osv-scanner as an MCP service (experimental)",
		Description: "Run osv-scanner as an MCP service, speaking the MCP protocol over stdin/stdout.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "sse",
				DefaultText: "localhost:8080",
				Value:       "localhost:8080",
				Usage:       "The listening address for the SSE server, e.g. localhost:8080",
			},
		},
		Action: action,
	}
}

type ScanVulnerableDependenciesInput struct {
	Paths              []string `json:"paths"                jsonschema:"A list of absolute or relative path to a file or directory to scan.,required"`
	IgnoreGlobPatterns []string `json:"ignore_glob_patterns" jsonschema:"A list of glob patterns to ignore when scanning."`
	Recursive          bool     `json:"recursive"            jsonschema:"Scans directory recursively"`
}

type GetVulnerabilityDetailsInput struct {
	VulnID string `json:"vuln_id" jsonschema:"The OSV vulnerability ID to retrieve details for.,required"`
}

func action(ctx context.Context, cmd *cli.Command) error {
	s := mcp.NewServer(&mcp.Implementation{
		Name: "OSV-Scanner", Version: version.OSVVersion,
	}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name: "scan_vulnerable_dependencies",
		Description: "Scans a source directory for vulnerable dependencies." +
			" Walks the given directory and uses osv.dev to query for vulnerabilities matching the found dependencies." +
			" Use this tool to check that the user's project is not depending on known vulnerable code.",
	}, handleScan)

	// TODO(another-rex): Ideally this would be a template resource, but gemini-cli does not support those yet.
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_vulnerability_details",
		Description: "Retrieves the full JSON details for a given vulnerability ID.",
	}, handleVulnIDRetrieval)

	s.AddPrompt(&mcp.Prompt{
		Name:        "scan_deps",
		Description: "Scans your project dependencies for known vulnerabilities.",
	}, handleCodeReview)

	if cmd.IsSet("sse") {
		sseAddr := cmd.String("sse")
		cmdlogger.Infof("Starting SSE server on %s", sseAddr)
		handler := mcp.NewSSEHandler(func(_ *http.Request) *mcp.Server {
			return s
		}, nil)
		//nolint:gosec // Having no timeouts is unlikely to cause problems as this is meant to be run locally.
		if err := http.ListenAndServe(sseAddr, handler); err != nil {
			cmdlogger.Errorf("mcp error: %s", err)
			return err
		}
	} else {
		cmdlogger.SendEverythingToStderr()
		cmdlogger.Infof("Starting MCP server on stdio")
		if err := s.Run(ctx, &mcp.StdioTransport{}); err != nil {
			cmdlogger.Errorf("mcp error: %s", err)
			return err
		}
	}

	return nil
}

func handleScan(_ context.Context, _ *mcp.CallToolRequest, input *ScanVulnerableDependenciesInput) (*mcp.CallToolResult, any, error) {
	statsCollector := fileOpenedLogger{}

	action := osvscanner.ScannerActions{
		DirectoryPaths:      input.Paths,
		ScanLicensesSummary: false,
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			StatsCollector: &statsCollector,
		},
		CallAnalysisStates: map[string]bool{
			"go": true,
		},
		Recursive: input.Recursive,
	}

	//nolint:contextcheck // passing the context in would be a breaking change
	scanResults, err := osvscanner.DoScan(action)
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		return nil, nil, fmt.Errorf("failed to run scanner: %w", err)
	}

	for _, vuln := range scanResults.Flatten() {
		vulnCacheMap[vuln.Vulnerability.ID] = &vuln.Vulnerability
	}

	if err == nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "No issues found"},
			},
		}, nil, nil
	}

	buf := strings.Builder{}

	for _, s := range statsCollector.collectedLines {
		buf.WriteString(s + "\n")
	}

	text.DisableColors()
	output.PrintVerticalResults(&scanResults, &buf, false)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: buf.String()},
		},
	}, nil, nil
}

func handleVulnIDRetrieval(ctx context.Context, _ *mcp.CallToolRequest, input *GetVulnerabilityDetailsInput) (*mcp.CallToolResult, *osvschema.Vulnerability, error) {
	vuln, found := vulnCacheMap[input.VulnID]
	if !found {
		var err error
		vuln, err = osvdev.DefaultClient().GetVulnByID(ctx, input.VulnID)
		if err != nil {
			return nil, nil, fmt.Errorf("vulnerability with ID %s not found: %w", input.VulnID, err)
		}

		vulnCacheMap[input.VulnID] = vuln
	}

	return &mcp.CallToolResult{}, vuln, nil
}

func handleCodeReview(_ context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{
		Description: "Dependency vulnerability analysis",
		Messages: []*mcp.PromptMessage{
			{
				Role: "assistant",
				Content: &mcp.TextContent{
					Text: `

You are a highly skilled senior security analyst.
Your primary task is to conduct a security audit of the vulnerabilities in the dependencies of this project.
Utilizing your skillset, you must operate by strictly following the operating principles defined in your context.

**Step 1: Perform initial scan**

Use the scan_vulnerable_dependencies with recursive on the project, always use the absolute path.
This will return a report of all the relevant lockfiles and all vulnerable dependencies in those files.

**Step 2: Analyse the report**

Go through the report and determine the relevant project lockfiles (ignoring lockfiles in test directories),
and prioritise which vulnerability to fix based on the description and severity.
If more information is needed about a vulnerability, use get_vulnerability_details.

**Step 3: Prioritisation**

Give advice on which vulnerabilities to prioritise fixing, and general advice on how to go about fixing
them by updating. Don't try to automatically update for the user without input.
`,
				},
			},
		},
	}, nil
}
