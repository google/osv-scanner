// Package mcp implements the `mcp` command for osv-scanner.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/urfave/cli/v3"
	"osv.dev/bindings/go/osvdev"
)

var vulnCacheMap = map[string]*osvschema.Vulnerability{}

func Command(_, _ io.Writer) *cli.Command {
	return &cli.Command{
		Name:        "mcp",
		Usage:       "Run osv-scanner as an MCP service",
		Description: "Run osv-scanner as an MCP service, speaking the MCP protocol over stdin/stdout.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "sse",
				DefaultText: "localhost:8080",
				Value:       "localhost:8080",
				Usage:       "The listening address for the SSE server, e.g. localhost:8080",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return action(ctx, cmd)
		},
	}
}

func action(ctx context.Context, cmd *cli.Command) error {
	s := server.NewMCPServer("OSV-Scanner", version.OSVVersion,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
	)

	s.AddTool(
		mcp.NewTool("scan_vulnerable_dependencies",
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithOpenWorldHintAnnotation(true),
			mcp.WithDescription("Scans a source directory for vulnerable dependencies."+
				" Walks the given directory and uses osv.dev to query for vulnerabilities matching the found dependencies."+
				" Use this tool to check that the user's project is not depending on known vulnerable code."),
			mcp.WithArray("paths",
				mcp.WithStringItems(),
				mcp.Required(),
				mcp.Description("A list of absolute or relative path to a file or directory to scan."),
			),
			mcp.WithArray("ignore_glob_patterns",
				mcp.WithStringItems(),
				mcp.Description("A list of glob patterns to ignore when scanning."),
			),
			mcp.WithBoolean("recursive",
				mcp.DefaultBool(false),
				mcp.Description("Scans directory recursively"),
			),
		),
		handleScan,
	)

	// TODO(another-rex): Ideally this would be a template resource, but gemini-cli does not support those yet.
	s.AddTool(
		mcp.NewTool("get_vulnerability_details",
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDescription(
				"Retrieves the full JSON details for a given vulnerability ID."),
			mcp.WithString("vuln_id",
				mcp.Required(),
				mcp.Description("The OSV vulnerability ID to retrieve details for."),
			),
		),
		handleVulnIDRetrieval,
	)

	s.AddPrompt(
		mcp.NewPrompt("scan_deps",
			mcp.WithPromptDescription("Scans your project dependencies for known vulnerabilities."),
		),
		handleCodeReview,
	)

	if cmd.IsSet("sse") {
		sseAddr := cmd.String("sse")
		sseServer := server.NewSSEServer(s)
		cmdlogger.Infof("Starting SSE server on %s", sseAddr)
		if err := sseServer.Start(sseAddr); err != nil {
			cmdlogger.Errorf("mcp error: %s", err)
			return err
		}
	} else {
		cmdlogger.SendEverythingToStderr()
		cmdlogger.Infof("Starting MCP server on stdio")
		if err := server.ServeStdio(s); err != nil {
			cmdlogger.Errorf("mcp error: %s", err)
			return err
		}
	}

	return nil
}

func handleScan(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireStringSlice("paths")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	recursive, err := req.RequireBool("recursive")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Security: validate path
	// if !isValidPath(path) {
	//	return mcp.NewToolResultError(fmt.Sprintf("invalid path: %s", path)), nil
	//}

	statsCollector := fileOpenedLogger{}

	action := osvscanner.ScannerActions{
		DirectoryPaths:      path,
		ScanLicensesSummary: true,
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			StatsCollector: &statsCollector,
		},
		CallAnalysisStates: map[string]bool{
			"go": false,
		},
		Recursive: recursive,
	}

	//nolint:contextcheck // passing the context in would be a breaking change
	scanResults, err := osvscanner.DoScan(action)
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		return mcp.NewToolResultError(fmt.Sprintf("failed to run scanner: %v", err)), nil
	}

	for _, vuln := range scanResults.Flatten() {
		vulnCacheMap[vuln.Vulnerability.ID] = &vuln.Vulnerability
	}

	if err == nil {
		return mcp.NewToolResultText("No issues found"), nil
	}

	buf := strings.Builder{}

	for _, s := range statsCollector.collectedLines {
		buf.WriteString(s + "\n")
	}

	text.DisableColors()
	output.PrintVerticalResults(&scanResults, &buf, false)
	//if err != nil {
	//	return mcp.NewToolResultError(fmt.Sprintf("failed to format result scanner: %v", err)), nil
	//}

	return mcp.NewToolResultText(buf.String()), nil
}

func handleVulnIDRetrieval(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	vulnID, err := req.RequireString("vuln_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	vuln, found := vulnCacheMap[vulnID]
	if !found {
		vuln, err = osvdev.DefaultClient().GetVulnByID(ctx, vulnID)
		if err != nil {
			mcp.NewToolResultError(fmt.Sprintf("vulnerability with ID %s not found in cache: %v", vulnID, err))
		}

		vulnCacheMap[vulnID] = vuln
	}

	jsonBytes, err := vuln.MarshalJSON()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal vulnerability details: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonBytes)), nil
}

func handleCodeReview(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {

	return &mcp.GetPromptResult{
		Description: "Dependency vulnerability analysis",
		Messages: []mcp.PromptMessage{
			{
				Role: mcp.RoleAssistant,
				Content: mcp.NewTextContent(`

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
them by updating.

`),
			},
		},
	}, nil
}
