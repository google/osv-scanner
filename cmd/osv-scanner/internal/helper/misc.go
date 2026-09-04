// Package helper provides helper functions for the osv-scanner CLI.
package helper

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/reporter"
	"github.com/google/osv-scanner/v2/pkg/models"
	"golang.org/x/term"
)

// sets default port(8000) as a global variable
var (
	servePort = "8000" // default port
)

// ServeHTML serves the single HTML file for remote accessing.
// The program will keep running to serve the HTML report on localhost
// until the user manually terminates it (e.g. using Ctrl+C).
func ServeHTML(outputPath string) {
	localhostURL := fmt.Sprintf("http://localhost:%s/", servePort)
	cmdlogger.Infof("Serving HTML report at %s", localhostURL)
	cmdlogger.Infof("If you are accessing remotely, use the following SSH command:")
	cmdlogger.Infof("`ssh -L local_port:destination_server_ip:%s ssh_server_hostname`", servePort)
	server := &http.Server{
		Addr: ":" + servePort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, outputPath)
		}),
		ReadHeaderTimeout: 3 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		cmdlogger.Errorf("Failed to start server: %v", err)
	}
}

func PrintResult(stdout, stderr io.Writer, outputPath, format string, diffVulns *models.VulnerabilityResults, showAllVulns bool) error {
	termWidth := 0
	var err error
	if outputPath != "" { // Output is definitely a file
		stdout, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
	} else { // Output might be a terminal
		if stdoutAsFile, ok := stdout.(*os.File); ok {
			termWidth, _, err = term.GetSize(int(stdoutAsFile.Fd()))
			if err != nil { // If output is not a terminal,
				termWidth = 0
			}
		}
	}

	writer := stdout

	if format == "gh-annotations" {
		writer = stderr
	}

	return reporter.PrintResult(diffVulns, format, writer, termWidth, showAllVulns)
}
