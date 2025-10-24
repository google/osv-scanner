// Package mcp implements the `mcp` command for osv-scanner.
package mcp

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

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

// vulnCacheMap is a cache of vulnerability details that have been retrieved from the OSV API during normal scanning.
// This avoids unnecessary double queries to the osv.dev API.
// vulnCacheMap: map[string]*osvschema.Vulnerability
var vulnCacheMap = sync.Map{}

// Command is the entry point for the `mcp` subcommand.
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

// scanVulnerableDependenciesInput is the input for the scan_vulnerable_dependencies tool.
type scanVulnerableDependenciesInput struct {
	Paths              []string `json:"paths"                jsonschema:"A list of absolute or relative path to a file or directory to scan."`
	IgnoreGlobPatterns []string `json:"ignore_glob_patterns" jsonschema:"A list of glob patterns to ignore when scanning."`
	Recursive          bool     `json:"recursive"            jsonschema:"Scans directory recursively"`
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

	// TODO(another-rex): Ideally both of the following tools would be resources, but gemini-cli does not support those yet.
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_vulnerability_details",
		Description: "Retrieves the full JSON details for a given vulnerability ID.",
	}, handleVulnIDRetrieval)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "ignore_vulnerability",
		Description: "Provides instructions for writing a config file to exclude vulnerabilities from the scan report.",
	}, handleIgnoreVulnerability)

	s.AddPrompt(&mcp.Prompt{
		Name:        "scan_deps",
		Description: "Scans your project dependencies for known vulnerabilities.",
	}, handleScanDepsPrompt)

	// Provide two options, sse on a network port, or stdio.
	if cmd.IsSet("sse") {
		sseAddr := cmd.String("sse")
		cmdlogger.Infof("Starting SSE server on %s", sseAddr)
		handler := mcp.NewSSEHandler(func(_ *http.Request) *mcp.Server {
			return s
		}, nil)
		srv := &http.Server{
			Addr:         sseAddr,
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		if err := srv.ListenAndServe(); err != nil {
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

func handleScan(_ context.Context, _ *mcp.CallToolRequest, input *scanVulnerableDependenciesInput) (*mcp.CallToolResult, any, error) {
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
		vulnCacheMap.Store(vuln.Vulnerability.ID, &vuln.Vulnerability)
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

// getVulnerabilityDetailsInput is the input for the get_vulnerability_details tool.
type getVulnerabilityDetailsInput struct {
	VulnID string `json:"vuln_id" jsonschema:"The OSV vulnerability ID to retrieve details for."`
}

func handleVulnIDRetrieval(ctx context.Context, _ *mcp.CallToolRequest, input *getVulnerabilityDetailsInput) (*mcp.CallToolResult, *osvschema.Vulnerability, error) {
	vulnAny, found := vulnCacheMap.Load(input.VulnID)
	vuln := vulnAny.(*osvschema.Vulnerability)
	if !found {
		var err error
		vuln, err = osvdev.DefaultClient().GetVulnByID(ctx, input.VulnID)
		if err != nil {
			return nil, nil, fmt.Errorf("vulnerability with ID %s not found: %w", input.VulnID, err)
		}

		vulnCacheMap.Store(input.VulnID, vuln)
	}

	return &mcp.CallToolResult{}, vuln, nil
}

// ignoreVulnerabilityInput is a placeholder to enable the tool call,
// as it seems like go-sdk mcp does not support a tool call with no arguments.
type ignoreVulnerabilityInput struct {
	// Extra field is needed as a placeholder to prevent the llm from erroring when calling the tool
	Verbose bool `json:"verbose" jsonschema:"ignore this parameter"`
}

//go:embed configuration-instructions.md
var configInstructions string

// handleIgnoreVulnerability does not perform any actual actions, but instead provides the instructions of how
// to write an ignore file to the LLM using this tool, so that it can correctly write the ignore file.
func handleIgnoreVulnerability(_ context.Context, _ *mcp.CallToolRequest, _ *ignoreVulnerabilityInput) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: configInstructions},
		},
	}, nil, nil
}

// scanDepsPrompt is the prompt that is sent to the AI model when the scan_deps prompt is requested.
//
//go:embed scan-deps-prompt.md
var scanDepsPrompt string

func handleScanDepsPrompt(_ context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return &mcp.GetPromptResult{
		Description: "Dependency vulnerability analysis",
		Messages: []*mcp.PromptMessage{
			{
				Role: "assistant",
				Content: &mcp.TextContent{
					Text: scanDepsPrompt,
				},
			},
		},
	}, nil
}
