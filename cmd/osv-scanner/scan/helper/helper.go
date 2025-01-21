package helper

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/google/osv-scanner/pkg/reporter"
)

// flags that require network access and values to disable them.
var OfflineFlags = map[string]string{
	"skip-git":                             "true",
	"experimental-offline-vulnerabilities": "true",
	"experimental-no-resolve":              "true",
	"experimental-licenses-summary":        "false",
	// "experimental-licenses": "", // StringSliceFlag has to be manually cleared.
}

// openHTML opens the outputted HTML file.
func OpenHTML(r reporter.Reporter, outputPath string) {
	// Open the outputted HTML file in the default browser.
	r.Infof("Opening %s...\n", outputPath)
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", outputPath).Start()
	case "windows":
		err = exec.Command("start", "", outputPath).Start()
	case "darwin": // macOS
		err = exec.Command("open", outputPath).Start()
	default:
		r.Infof("Unsupported OS.\n")
	}

	if err != nil {
		r.Errorf("Failed to open: %s.\n Please manually open the outputted HTML file: %s\n", err, outputPath)
	}
}

// Serve the single HTML file for remote accessing.
// The program will keep running to serve the HTML report on localhost
// until the user manually terminates it (e.g. using Ctrl+C).
func ServeHTML(r reporter.Reporter, outputPath string) {
	servePort := "8000"
	localhostURL := fmt.Sprintf("http://localhost:%s/", servePort)
	r.Infof("Serving HTML report at %s.\nIf you are accessing remotely, use the following SSH command:\n`ssh -L local_port:destination_server_ip:%s ssh_server_hostname`\n", localhostURL, servePort)
	server := &http.Server{
		Addr: ":" + servePort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, outputPath)
		}),
		ReadHeaderTimeout: 3 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		r.Errorf("Failed to start server: %v\n", err)
	}
}
