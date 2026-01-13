package mcp_test

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestIntegration_MCP_SSE_Subprocess validates the experimental-mcp command by:
// 1. Building the binary.
// 2. Starting it as an MCP server.
// 3. Connecting a client.
// 4. Running tools (scan_vulnerable_dependencies, get_vulnerability_details).
func TestIntegration_MCP_SSE_Subprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	binPath := buildTestBinary(t)
	addr := findFreePort(t)

	// Start the server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmdRun := startMCPServer(t, ctx, binPath, addr)
	defer func() {
		cancel()
		_ = cmdRun.Wait()
	}()

	// Wait for server to be ready
	baseURL := "http://" + addr + "/sse"
	waitForServer(t, baseURL)

	// Connect Client
	client := connectMCPClient(t, ctx, baseURL)
	defer client.Close()

	// Use persistent testdata/go-project
	testDataPath, err := filepath.Abs("testdata/go-project")
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}
	if _, err := os.Stat(testDataPath); os.IsNotExist(err) {
		t.Fatalf("testdata/go-project does not exist at %s", testDataPath)
	}

	var vulnID string

	// Step 1: Scan for vulnerabilities
	t.Run("ScanVulnerableDependencies", func(t *testing.T) {
		scanResult, err := client.CallTool(ctx, &mcp.CallToolParams{
			Name: "scan_vulnerable_dependencies",
			Arguments: map[string]any{
				"paths":                []string{testDataPath},
				"recursive":            true,
				"ignore_glob_patterns": []string{},
			},
		})
		if err != nil {
			t.Fatalf("call to scan_vulnerable_dependencies failed: %v", err)
		}

		if len(scanResult.Content) == 0 {
			t.Fatal("scan result content is empty")
		}

		textRes, ok := scanResult.Content[0].(*mcp.TextContent)
		if !ok {
			t.Fatalf("expected TextContent, got %T", scanResult.Content[0])
		}

		output := textRes.Text
		t.Logf("Scan completed. Output length: %d", len(output))
		testutility.NewSnapshot().MatchText(t, output)

		// Extract a vulnerability ID for the next step.
		// Example: GHSA-f682-3w9h-r22r or GO-2023-1558
		re := regexp.MustCompile(`(GHSA-[a-zA-Z0-9-]+|GO-\d{4}-\d+)`)
		vulnID = re.FindString(output)
	})

	if vulnID == "" {
		t.Fatal("cannot test get_vulnerability_details without a valid ID found in scan output")
	}
	t.Logf("Found Vuln ID: %s", vulnID)

	// Step 2: Get details for the found vulnerability
	t.Run("GetVulnerabilityDetails", func(t *testing.T) {
		detailsResult, err := client.CallTool(ctx, &mcp.CallToolParams{
			Name: "get_vulnerability_details",
			Arguments: map[string]any{
				"vuln_id": vulnID,
			},
		})
		if err != nil {
			t.Fatalf("call to get_vulnerability_details failed: %v", err)
		}

		if len(detailsResult.Content) == 0 {
			t.Log("Details Result Content is empty")
			return
		}

		t.Logf("Details Result Content: %v", detailsResult.Content[0])
		testutility.NewSnapshot().MatchJSON(t, detailsResult)
	})
}

// buildTestBinary builds the osv-scanner binary to a temporary directory.
func buildTestBinary(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "osv-scanner-mcp-test")

	// We use the full package path to ensure we build the correct main package.
	cmdBuild := exec.Command("go", "build", "-o", binPath, "github.com/google/osv-scanner/v2/cmd/osv-scanner")
	cmdBuild.Stdout = os.Stdout
	cmdBuild.Stderr = os.Stderr
	if err := cmdBuild.Run(); err != nil {
		t.Fatalf("failed to build binary: %v", err)
	}

	return binPath
}

// findFreePort lets the OS choose a free port and returns the address string (e.g. "127.0.0.1:12345").
func findFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	return addr
}

// startMCPServer starts the mcp server in a subprocess.
func startMCPServer(t *testing.T, ctx context.Context, binPath, addr string) *exec.Cmd {
	t.Helper()
	cmdRun := exec.CommandContext(ctx, binPath, "experimental-mcp", "--sse", addr)
	cmdRun.Stderr = os.Stderr
	cmdRun.Stdout = os.Stdout

	t.Logf("Starting MCP server on %s", addr)
	if err := cmdRun.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	return cmdRun
}

// connectMCPClient connects to the MCP server via SSE.
func connectMCPClient(t *testing.T, ctx context.Context, baseURL string) *mcp.ClientSession {
	t.Helper()
	transport := &mcp.SSEClientTransport{
		Endpoint: baseURL,
	}

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "1.0.0",
	}, nil)

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("failed to connect to MCP server: %v", err)
	}

	return session
}

func waitForServer(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server failed to start listening at %s within timeout", url)
}
