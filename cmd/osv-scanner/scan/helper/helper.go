package helper

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/urfave/cli/v2"
)

// flags that require network access and values to disable them.
var OfflineFlags = map[string]string{
	"skip-git":                             "true",
	"experimental-offline-vulnerabilities": "true",
	"experimental-no-resolve":              "true",
	"experimental-licenses-summary":        "false",
	// "experimental-licenses": "", // StringSliceFlag has to be manually cleared.
}

var GlobalScanFlags = []cli.Flag{
	&cli.StringFlag{
		Name:      "config",
		Usage:     "set/override config file",
		TakesFile: true,
	},
	&cli.StringFlag{
		Name:    "format",
		Aliases: []string{"f"},
		Usage:   "sets the output format; value can be: " + strings.Join(reporter.Format(), ", "),
		Value:   "table",
		Action: func(_ *cli.Context, s string) error {
			if slices.Contains(reporter.Format(), s) {
				return nil
			}

			return fmt.Errorf("unsupported output format \"%s\" - must be one of: %s", s, strings.Join(reporter.Format(), ", "))
		},
	},
	&cli.BoolFlag{
		Name:  "serve",
		Usage: "output as HTML result and serve it locally",
	},
	&cli.StringFlag{
		Name:      "output",
		Usage:     "saves the result to the given file path",
		TakesFile: true,
	},
	&cli.StringFlag{
		Name:  "verbosity",
		Usage: "specify the level of information that should be provided during runtime; value can be: " + strings.Join(reporter.VerbosityLevels(), ", "),
		Value: "info",
	},
	&cli.BoolFlag{
		Name:  "experimental-offline",
		Usage: "run in offline mode, disabling any features requiring network access",
		Action: func(ctx *cli.Context, b bool) error {
			if !b {
				return nil
			}
			// Disable the features requiring network access.
			for flag, value := range OfflineFlags {
				// TODO(michaelkedar): do something if the flag was already explicitly set.
				if err := ctx.Set(flag, value); err != nil {
					panic(fmt.Sprintf("failed setting offline flag %s to %s: %v", flag, value, err))
				}
			}

			return nil
		},
	},
	&cli.BoolFlag{
		Name:  "experimental-offline-vulnerabilities",
		Usage: "checks for vulnerabilities using local databases that are already cached",
	},
	&cli.BoolFlag{
		Name:  "experimental-download-offline-databases",
		Usage: "downloads vulnerability databases for offline comparison",
	},
	&cli.BoolFlag{
		Name:  "experimental-no-resolve",
		Usage: "disable transitive dependency resolution of manifest files",
	},
	&cli.StringFlag{
		Name:   "experimental-local-db-path",
		Usage:  "sets the path that local databases should be stored",
		Hidden: true,
	},
	&cli.BoolFlag{
		Name:  "experimental-all-packages",
		Usage: "when json output is selected, prints all packages",
	},
	&cli.BoolFlag{
		Name:  "experimental-licenses-summary",
		Usage: "report a license summary, implying the --experimental-all-packages flag",
	},
	&cli.StringSliceFlag{
		Name:  "experimental-licenses",
		Usage: "report on licenses based on an allowlist",
	},
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
