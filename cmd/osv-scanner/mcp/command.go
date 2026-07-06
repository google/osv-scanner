// Package mcp implements the `mcp` command for osv-scanner.
package mcp

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/output"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/tidwall/pretty"
	"github.com/urfave/cli/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"osv.dev/bindings/go/osvdev"
)

var (
	vulnCacheMu  sync.RWMutex
	vulnCacheMap = make(map[string]*osvschema.Vulnerability)
)

// Command is the entry point for the `mcp` subcommand.
func Command(_, _ io.Writer, _ *http.Client) *cli.Command {
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
			&cli.StringFlag{
				Name:    "sse-token",
				Usage:   "Bearer token required by SSE clients. Required when --sse listens on a non-loopback address.",
				Sources: cli.EnvVars("OSV_SCANNER_MCP_SSE_TOKEN"),
			},
			&cli.StringSliceFlag{
				Name:  "workspace",
				Usage: "Workspace root that MCP scan paths must stay within. May be repeated.",
				Value: []string{"."},
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
	workspaceRoots, err := resolveWorkspaceRoots(cmd.StringSlice("workspace"))
	if err != nil {
		return err
	}
	scanner := scanHandler{workspaceRoots: workspaceRoots}

	s := mcp.NewServer(&mcp.Implementation{
		Name: "OSV-Scanner", Version: version.OSVVersion,
	}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name: "scan_vulnerable_dependencies",
		Description: "Scans a source directory for vulnerable dependencies." +
			" Walks the given directory and uses osv.dev to query for vulnerabilities matching the found dependencies." +
			" Use this tool to check that the user's project is not depending on known vulnerable code.",
	}, scanner.handleScan)

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
		sseToken := cmd.String("sse-token")
		if sseToken == "" && !isLoopbackListenAddr(sseAddr) {
			return fmt.Errorf("--sse-token or OSV_SCANNER_MCP_SSE_TOKEN is required when --sse listens on a non-loopback address")
		}

		cmdlogger.Infof("Starting SSE server on %s", sseAddr)
		handler := mcp.NewSSEHandler(func(_ *http.Request) *mcp.Server {
			return s
		}, nil)
		srv := &http.Server{
			Addr:         sseAddr,
			Handler:      requireBearerToken(handler, sseToken),
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

type scanHandler struct {
	workspaceRoots []string
}

func (h scanHandler) handleScan(_ context.Context, _ *mcp.CallToolRequest, input *scanVulnerableDependenciesInput) (*mcp.CallToolResult, any, error) {
	if input == nil {
		return nil, nil, errors.New("missing scan input")
	}

	scanPaths, err := h.validateScanPaths(input.Paths)
	if err != nil {
		return nil, nil, err
	}

	statsCollector := fileOpenedLogger{workspaceRoots: h.workspaceRoots}

	action := osvscanner.ScannerActions{
		DirectoryPaths:      scanPaths,
		ScanLicensesSummary: false,
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			ExcludePatterns: input.IgnoreGlobPatterns,
			StatsCollector:  &statsCollector,
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

	vulnCacheMu.Lock()
	for _, vuln := range scanResults.Flatten() {
		vulnCacheMap[vuln.Vulnerability.GetId()] = vuln.Vulnerability
	}
	vulnCacheMu.Unlock()

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
			&mcp.TextContent{Text: h.redactWorkspaceRoots(buf.String())},
		},
	}, nil, nil
}

func resolveWorkspaceRoots(paths []string) ([]string, error) {
	if len(paths) == 0 {
		paths = []string{"."}
	}

	roots := make([]string, 0, len(paths))
	for _, path := range paths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve workspace %q: %w", path, err)
		}

		resolvedPath, err := filepath.EvalSymlinks(absPath)
		if err != nil {
			return nil, fmt.Errorf("resolve workspace %q: %w", path, err)
		}

		info, err := os.Stat(resolvedPath)
		if err != nil {
			return nil, fmt.Errorf("stat workspace %q: %w", path, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("workspace %q is not a directory", path)
		}

		roots = append(roots, filepath.Clean(resolvedPath))
	}

	return roots, nil
}

func (h scanHandler) validateScanPaths(paths []string) ([]string, error) {
	scanPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		resolvedPath, err := resolveScanPath(path)
		if err != nil {
			return nil, err
		}
		if !pathInAnyRoot(resolvedPath, h.workspaceRoots) {
			return nil, fmt.Errorf("scan path %q is outside the configured MCP workspace", path)
		}

		scanPaths = append(scanPaths, resolvedPath)
	}

	return scanPaths, nil
}

func resolveScanPath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve scan path %q: %w", path, err)
	}

	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if err == nil {
		return filepath.Clean(resolvedPath), nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return filepath.Clean(absPath), nil
	}

	return "", fmt.Errorf("resolve scan path %q: %w", path, err)
}

func pathInAnyRoot(path string, roots []string) bool {
	for _, root := range roots {
		if pathInRoot(path, root) {
			return true
		}
	}

	return false
}

func pathInRoot(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}

	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func (h scanHandler) redactWorkspaceRoots(text string) string {
	return redactWorkspaceRoots(text, h.workspaceRoots)
}

func redactWorkspaceRoots(text string, roots []string) string {
	for _, root := range roots {
		text = strings.ReplaceAll(text, root, "<workspace>")
		text = strings.ReplaceAll(text, filepath.ToSlash(root), "<workspace>")
	}

	return text
}

func requireBearerToken(next http.Handler, token string) http.Handler {
	if token == "" {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// getVulnerabilityDetailsInput is the input for the get_vulnerability_details tool.
type getVulnerabilityDetailsInput struct {
	VulnID string `json:"vuln_id" jsonschema:"The OSV vulnerability ID to retrieve details for."`
}

func handleVulnIDRetrieval(ctx context.Context, _ *mcp.CallToolRequest, input *getVulnerabilityDetailsInput) (*mcp.CallToolResult, any, error) {
	vulnCacheMu.RLock()
	vuln, found := vulnCacheMap[input.VulnID]
	vulnCacheMu.RUnlock()
	if !found {
		var err error
		vuln, err = osvdev.DefaultClient().GetVulnByID(ctx, input.VulnID)
		if err != nil {
			return nil, nil, fmt.Errorf("vulnerability with ID %s not found: %w", input.VulnID, err)
		}

		vulnCacheMu.Lock()
		vulnCacheMap[input.VulnID] = vuln
		vulnCacheMu.Unlock()
	}

	jsonBytes, err := protojson.Marshal(vuln)
	if err != nil {
		return nil, nil, err
	}
	prettyJSON := pretty.Pretty(jsonBytes)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: string(prettyJSON),
			},
		},
	}, nil, nil
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
