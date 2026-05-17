package plugins

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/osv-scanner/v2/internal/scalibrplugin"
	"github.com/urfave/cli/v3"
)

func Command(stdout, _ io.Writer, _ *http.Client) *cli.Command {
	return &cli.Command{
		Name:        "plugins",
		Usage:       "lists the available experimental plugin presets and exact plugin names",
		Description: "Lists the available experimental plugin presets and exact plugin names that can be passed to --experimental-plugins or --experimental-disable-plugins.",
		Commands: []*cli.Command{
			{
				Name:        "list",
				Usage:       "lists the available plugin presets and exact plugin names",
				Description: "Lists the available experimental plugin presets and exact plugin names that can be passed to --experimental-plugins or --experimental-disable-plugins.",
				Action: func(_ context.Context, _ *cli.Command) error {
					printPluginCatalog(stdout)
					return nil
				},
			},
		},
	}
}

func printPluginCatalog(stdout io.Writer) {
	fmt.Fprintln(stdout, "Available plugin presets:")
	fmt.Fprintf(stdout, "  extractors: %s\n", strings.Join(scalibrplugin.ExtractorPresetNames(), ", "))
	fmt.Fprintf(stdout, "  detectors: %s\n", strings.Join(scalibrplugin.DetectorPresetNames(), ", "))
	fmt.Fprintf(stdout, "  annotators: %s\n", strings.Join(scalibrplugin.AnnotatorPresetNames(), ", "))
	fmt.Fprintf(stdout, "  enrichers: %s\n", strings.Join(scalibrplugin.EnricherPresetNames(), ", "))
	fmt.Fprintln(stdout)

	fmt.Fprintln(stdout, "Available exact plugin names:")
	for _, name := range scalibrplugin.PluginNames() {
		fmt.Fprintf(stdout, "  %s\n", name)
	}
}
