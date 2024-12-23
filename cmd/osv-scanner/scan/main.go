package scan

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/google/osv-scanner/internal/spdx"
	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/google/osv-scanner/pkg/reporter"
	"golang.org/x/term"

	"github.com/urfave/cli/v2"
)

// flags that require network access and values to disable them.
var offlineFlags = map[string]string{
	"skip-git":                             "true",
	"experimental-offline-vulnerabilities": "true",
	"experimental-no-resolve":              "true",
	"experimental-licenses-summary":        "false",
	// "experimental-licenses": "", // StringSliceFlag has to be manually cleared.
}

func Command(stdout, stderr io.Writer, r *reporter.Reporter) *cli.Command {
	return &cli.Command{
		Name:        "scan",
		Usage:       "scans various mediums for dependencies and matches it against the OSV database",
		Description: "scans various mediums for dependencies and matches it against the OSV database",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:      "docker",
				Aliases:   []string{"D"},
				Usage:     "scan docker image with this name. This is a convenience function which runs `docker save` before scanning the saved image using --oci-image",
				TakesFile: false,
			},
			&cli.StringSliceFlag{
				Name:      "lockfile",
				Aliases:   []string{"L"},
				Usage:     "scan package lockfile on this path",
				TakesFile: true,
			},
			&cli.StringSliceFlag{
				Name:      "sbom",
				Aliases:   []string{"S"},
				Usage:     "scan sbom file on this path",
				TakesFile: true,
			},
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

					// Supporting html output format without showing it in the help command.
					// TODO(gongh@): add html to reporter.Format()
					if s == "html" {
						return nil
					}

					return fmt.Errorf("unsupported output format \"%s\" - must be one of: %s", s, strings.Join(reporter.Format(), ", "))
				},
			},
			&cli.BoolFlag{
				Name:  "serve",
				Usage: "output as HTML result and serve it locally",
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "sets output to json (deprecated, use --format json instead)",
			},
			&cli.StringFlag{
				Name:      "output",
				Usage:     "saves the result to the given file path",
				TakesFile: true,
			},
			&cli.BoolFlag{
				Name:  "skip-git",
				Usage: "skip scanning git repositories",
				Value: false,
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "check subdirectories",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:  "experimental-call-analysis",
				Usage: "[Deprecated] attempt call analysis on code to detect only active vulnerabilities",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "no-ignore",
				Usage: "also scan files that would be ignored by .gitignore",
				Value: false,
			},
			&cli.StringSliceFlag{
				Name:  "call-analysis",
				Usage: "attempt call analysis on code to detect only active vulnerabilities",
			},
			&cli.StringSliceFlag{
				Name:  "no-call-analysis",
				Usage: "disables call graph analysis",
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
					for flag, value := range offlineFlags {
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
			&cli.StringFlag{
				Name:      "experimental-oci-image",
				Usage:     "scan an exported *docker* container image archive (exported using `docker save` command) file",
				TakesFile: true,
				Hidden:    true,
			},
			&cli.BoolFlag{
				Name:  "experimental-no-resolve",
				Usage: "disable transitive dependency resolution of manifest files",
			},
			&cli.StringFlag{
				Name:  "experimental-resolution-data-source",
				Usage: "source to fetch package information from; value can be: deps.dev, native",
				Value: "deps.dev",
				Action: func(_ *cli.Context, s string) error {
					if s != "deps.dev" && s != "native" {
						return fmt.Errorf("unsupported data-source \"%s\" - must be one of: deps.dev, native", s)
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:  "experimental-maven-registry",
				Usage: "URL of the default registry to fetch Maven metadata",
			},
		},
		ArgsUsage: "[directory1 directory2...]",
		Action: func(c *cli.Context) error {
			var err error
			*r, err = action(c, stdout, stderr)

			return err
		},
	}
}

func action(context *cli.Context, stdout, stderr io.Writer) (reporter.Reporter, error) {
	format := context.String("format")

	if context.Bool("json") {
		format = "json"
	}

	outputPath := context.String("output")
	serve := context.Bool("serve")
	if serve {
		format = "html"
		if outputPath == "" {
			// Create a temporary directory
			tmpDir, err := os.MkdirTemp("", "osv-scanner-result")
			if err != nil {
				return nil, fmt.Errorf("failed creating temporary directory: %w\n"+
					"Please use `--output result.html` to specify the output path", err)
			}

			// Remove the created temporary directory after
			defer os.RemoveAll(tmpDir)
			outputPath = filepath.Join(tmpDir, "index.html")
		}
	}

	termWidth := 0
	var err error
	if outputPath != "" { // Output is definitely a file
		stdout, err = os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
	} else { // Output might be a terminal
		if stdoutAsFile, ok := stdout.(*os.File); ok {
			termWidth, _, err = term.GetSize(int(stdoutAsFile.Fd()))
			if err != nil { // If output is not a terminal,
				termWidth = 0
			}
		}
	}

	if context.Bool("experimental-licenses-summary") && context.IsSet("experimental-licenses") {
		return nil, errors.New("--experimental-licenses-summary and --experimental-licenses flags cannot be set")
	}
	allowlist := context.StringSlice("experimental-licenses")
	if context.IsSet("experimental-licenses") {
		if len(allowlist) == 0 ||
			(len(allowlist) == 1 && allowlist[0] == "") {
			return nil, errors.New("--experimental-licenses requires at least one value")
		}
		if unrecognized := spdx.Unrecognized(allowlist); len(unrecognized) > 0 {
			return nil, fmt.Errorf("--experimental-licenses requires comma-separated spdx licenses. The following license(s) are not recognized as spdx: %s", strings.Join(unrecognized, ","))
		}
	}

	verbosityLevel, err := reporter.ParseVerbosityLevel(context.String("verbosity"))
	if err != nil {
		return nil, err
	}
	r, err := reporter.New(format, stdout, stderr, verbosityLevel, termWidth)
	if err != nil {
		return r, err
	}

	var callAnalysisStates map[string]bool
	if context.IsSet("experimental-call-analysis") {
		callAnalysisStates = createCallAnalysisStates([]string{"all"}, context.StringSlice("no-call-analysis"))
		r.Infof("Warning: the experimental-call-analysis flag has been replaced. Please use the call-analysis and no-call-analysis flags instead.\n")
	} else {
		callAnalysisStates = createCallAnalysisStates(context.StringSlice("call-analysis"), context.StringSlice("no-call-analysis"))
	}

	scanLicensesAllowlist := context.StringSlice("experimental-licenses")
	if context.Bool("experimental-offline") {
		scanLicensesAllowlist = []string{}
	}

	vulnResult, err := osvscanner.DoScan(osvscanner.ScannerActions{
		LockfilePaths:      context.StringSlice("lockfile"),
		SBOMPaths:          context.StringSlice("sbom"),
		DockerImageName:    context.String("docker"),
		Recursive:          context.Bool("recursive"),
		SkipGit:            context.Bool("skip-git"),
		NoIgnore:           context.Bool("no-ignore"),
		ConfigOverridePath: context.String("config"),
		DirectoryPaths:     context.Args().Slice(),
		CallAnalysisStates: callAnalysisStates,
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			LocalDBPath:       context.String("experimental-local-db-path"),
			DownloadDatabases: context.Bool("experimental-download-offline-databases"),
			CompareOffline:    context.Bool("experimental-offline-vulnerabilities"),
			// License summary mode causes all
			// packages to appear in the json as
			// every package has a license - even
			// if it's just the UNKNOWN license.
			ShowAllPackages: context.Bool("experimental-all-packages") ||
				context.Bool("experimental-licenses-summary"),
			ScanLicensesSummary:   context.Bool("experimental-licenses-summary"),
			ScanLicensesAllowlist: scanLicensesAllowlist,
			ScanOCIImage:          context.String("experimental-oci-image"),
			TransitiveScanningActions: osvscanner.TransitiveScanningActions{
				Disabled:         context.Bool("experimental-no-resolve"),
				NativeDataSource: context.String("experimental-resolution-data-source") == "native",
				MavenRegistry:    context.String("experimental-maven-registry"),
			},
		},
	}, r)

	if err != nil && !errors.Is(err, osvscanner.VulnerabilitiesFoundErr) {
		return r, err
	}

	if errPrint := r.PrintResult(&vulnResult); errPrint != nil {
		return r, fmt.Errorf("failed to write output: %w", errPrint)
	}

	// Auto-open outputted HTML file for users.
	if outputPath != "" {
		if serve {
			serveHTML(r, outputPath)
		} else if format == "html" {
			openHTML(r, outputPath)
		}
	}

	// This may be nil.
	return r, err
}

// openHTML opens the outputted HTML file.
func openHTML(r reporter.Reporter, outputPath string) {
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
func serveHTML(r reporter.Reporter, outputPath string) {
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
