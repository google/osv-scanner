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
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/urfave/cli/v3"
)

var vulnCacheMap = map[string]*osvschema.Vulnerability{}

func Command(_, _ io.Writer) *cli.Command {
	return &cli.Command{
		Name:        "mcp",
		Usage:       "Run osv-scanner as an MCP service",
		Description: "Run osv-scanner as an MCP service, speaking the MCP protocol over stdin/stdout.",
		Action: func(_ context.Context, _ *cli.Command) error {
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
				scanSource,
			)

			// TODO(another-rex): Ideally this would be a template resource, but gemini-cli does not support those yet.
			s.AddTool(
				mcp.NewTool("get_vulnerability_details",
					mcp.WithReadOnlyHintAnnotation(true),
					mcp.WithDescription(
						"Retrieves the full JSON details for a given vulnerability ID from the cache of a previous scan."),
					mcp.WithString("vuln_id",
						mcp.Required(),
						mcp.Description("The OSV vulnerability ID to retrieve details for."),
					),
				),
				handleVulnIDRetrieval,
			)

			sseServer := server.NewSSEServer(s)
			// Start STDIO server

			cmdlogger.Infof("Starting server")
			if err := sseServer.Start("localhost:6659"); err != nil {
				cmdlogger.Errorf("mcp error: %s", err)
				return err
			}

			return nil
		},
	}
}

func scanSource(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
	err = output.PrintMCPReport(&scanResults, statsCollector.collectedLines, &buf)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to format result scanner: %v", err)), nil
	}

	return mcp.NewToolResultText(buf.String()), nil
}

func handleVulnIDRetrieval(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	vulnID, err := req.RequireString("vuln_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	vuln, found := vulnCacheMap[vulnID]
	if !found {
		return mcp.NewToolResultError(fmt.Sprintf("vulnerability with ID %s not found in cache", vulnID)), nil
	}

	jsonBytes, err := vuln.MarshalJSON()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal vulnerability details: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonBytes)), nil
}
