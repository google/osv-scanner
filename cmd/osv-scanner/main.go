package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/osv"
	"github.com/google/osv-scanner/internal/output"
	"github.com/google/osv-scanner/internal/sbom"
	"github.com/google/osv-scanner/pkg/lockfile"

	"github.com/urfave/cli/v2"
)

const osvScannerConfigName = "osv-scanner.toml"

// scanDir walks through the given directory to try to find any relevant files
// These include:
//   - Any lockfiles with scanLockfile
//   - Any SBOM files with scanSBOMFile
//   - Any git repositories with scanGit
func scanDir(r *output.Reporter, query *osv.BatchedQuery, dir string, skipGit bool, recursive bool) error {
	root := true
	return filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			r.PrintText(fmt.Sprintf("Failed to walk %s: %v\n", path, err))
			return err
		}
		path, err = filepath.Abs(path)
		if err != nil {
			r.PrintError(fmt.Sprintf("Failed to walk path %s\n", err))
			return err
		}

		if !skipGit && info.IsDir() && info.Name() == ".git" {
			err := scanGit(r, query, filepath.Dir(path)+"/")
			if err != nil {
				r.PrintText(fmt.Sprintf("scan failed for %s: %v\n", path, err))
				return err
			}
			return filepath.SkipDir
		}

		if !info.IsDir() {
			if parser, _ := lockfile.FindParser(path, ""); parser != nil {
				err := scanLockfile(r, query, path)
				if err != nil {
					r.PrintError(fmt.Sprintf("Attempted to scan lockfile but failed: %s\n", path))
				}
			}
			// No need to check for error
			// If scan fails, it means it isn't a valid SBOM file,
			// so just move onto the next file
			_ = scanSBOMFile(r, query, path)
		}

		if !root && !recursive && info.IsDir() {
			return filepath.SkipDir
		}
		root = false

		return nil
	})
}

// scanLockfile will load, identify, and parse the lockfile path passed in, and add the dependencies specified
// within to `query`
func scanLockfile(r *output.Reporter, query *osv.BatchedQuery, path string) error {
	parsedLockfile, err := lockfile.Parse(path, "")
	if err != nil {
		return err
	}
	r.PrintText(fmt.Sprintf("Scanned %s file and found %d packages\n", path, len(parsedLockfile.Packages)))

	for _, pkgDetail := range parsedLockfile.Packages {
		pkgDetailQuery := osv.MakePkgRequest(pkgDetail)
		pkgDetailQuery.Source = osv.Source{
			Path: path,
			Type: "lockfile",
		}
		query.Queries = append(query.Queries, pkgDetailQuery)
	}
	return nil
}

// scanSBOMFile will load, identify, and parse the SBOM path passed in, and add the dependencies specified
// within to `query`
func scanSBOMFile(r *output.Reporter, query *osv.BatchedQuery, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	for _, provider := range sbom.Providers {
		if provider.Name() == "SPDX" &&
			!strings.Contains(strings.ToLower(filepath.Base(path)), ".spdx") {
			// All spdx files should have the .spdx in the filename, even if
			// it's not the extension:  https://spdx.github.io/spdx-spec/v2.3/conformance/
			// Skip if this isn't the case to avoid panics
			continue
		}
		err := provider.GetPackages(file, func(id sbom.Identifier) error {
			purlQuery := osv.MakePURLRequest(id.PURL)
			purlQuery.Source = osv.Source{
				Path: path,
				Type: "sbom",
			}
			query.Queries = append(query.Queries, purlQuery)
			return nil
		})
		if err == nil {
			// Found the right format.
			r.PrintText(fmt.Sprintf("Scanned %s SBOM\n", provider.Name()))
			return nil
		}

		if errors.Is(err, sbom.InvalidFormat) {
			continue
		}

		return err
	}

	return nil
}

func getCommitSHA(repoDir string) (string, error) {
	cmd := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD")
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

// Scan git repository. Expects repoDir to end with /
func scanGit(r *output.Reporter, query *osv.BatchedQuery, repoDir string) error {
	commit, err := getCommitSHA(repoDir)
	if err != nil {
		return err
	}

	r.PrintText(fmt.Sprintf("Scanning %s at commit %s\n", repoDir, commit))

	gitQuery := osv.MakeCommitRequest(commit)
	gitQuery.Source = osv.Source{
		Path: repoDir,
		Type: "git",
	}
	query.Queries = append(query.Queries, gitQuery)
	return nil
}

func scanDebianDocker(r *output.Reporter, query *osv.BatchedQuery, dockerImageName string) error {
	cmd := exec.Command("docker", "run", "--rm", "--entrypoint", "/usr/bin/dpkg-query", dockerImageName, "-f", "${Package}###${Version}\\n", "-W")
	stdout, err := cmd.StdoutPipe()

	if err != nil {
		r.PrintError(fmt.Sprintf("Failed to get stdout: %s\n", err))
		return err
	}
	err = cmd.Start()
	if err != nil {
		r.PrintError(fmt.Sprintf("Failed to start docker image: %s\n", err))
		return err
	}
	defer cmd.Wait()
	if err != nil {
		r.PrintError(fmt.Sprintf("Failed to run docker: %s\n", err))
		return err
	}
	scanner := bufio.NewScanner(stdout)
	packages := 0
	for scanner.Scan() {
		text := scanner.Text()
		text = strings.TrimSpace(text)
		if len(text) == 0 {
			continue
		}
		splitText := strings.Split(text, "###")
		if len(splitText) != 2 {
			r.PrintError(fmt.Sprintf("Unexpected output from Debian container: \n\n%s\n", text))
			return fmt.Errorf("Unexpected output from Debian container: \n\n%s", text)
		}
		pkgDetailsQuery := osv.MakePkgRequest(lockfile.PackageDetails{
			Name:    splitText[0],
			Version: splitText[1],
			// TODO(rexpan): Get and specify exact debian release version
			Ecosystem: "Debian",
		})
		pkgDetailsQuery.Source = osv.Source{
			Path: dockerImageName,
			Type: "docker",
		}
		query.Queries = append(query.Queries, pkgDetailsQuery)
		packages += 1
	}
	r.PrintText(fmt.Sprintf("Scanned docker image with %d packages\n", packages))

	return nil
}

// Filters response according to config, returns number of responses removed
func filterResponse(r *output.Reporter, query osv.BatchedQuery, resp *osv.BatchedResponse, configManager *ConfigManager) int {
	hiddenVulns := map[string]IgnoreEntry{}

	for i, result := range resp.Results {
		var filteredVulns []osv.MinimalVulnerability
		configToUse := configManager.Get(query.Queries[i].Source.Path)
		for _, vuln := range result.Vulns {
			ignore, ignoreLine := configToUse.ShouldIgnore(vuln.ID)
			if ignore {
				hiddenVulns[vuln.ID] = ignoreLine
			} else {
				filteredVulns = append(filteredVulns, vuln)
			}
		}
		resp.Results[i].Vulns = filteredVulns
	}

	for id, ignoreLine := range hiddenVulns {
		r.PrintText(fmt.Sprintf("%s has been filtered out because: %s\n", id, ignoreLine.Reason))
	}

	return len(hiddenVulns)
}

func run(args []string, stdout, stderr io.Writer) int {
	var r *output.Reporter
	configManager := ConfigManager{
		defaultConfig: Config{},
		configMap:     make(map[string]Config),
	}
	var query osv.BatchedQuery

	app := &cli.App{
		Name:      "osv-scanner",
		Usage:     "scans various mediums for dependencies and matches it against the OSV database",
		Suggest:   true,
		Writer:    stdout,
		ErrWriter: stderr,
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:      "docker",
				Aliases:   []string{"D"},
				Usage:     "scan docker image with this name",
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
			&cli.BoolFlag{
				Name:  "json",
				Usage: "sets output to json (WIP)",
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
		},
		ArgsUsage: "[directory1 directory2...]",
		Action: func(context *cli.Context) error {
			r = output.NewReporter(stdout, stderr, context.Bool("json"))

			configPath := context.String("config")
			if configPath != "" {
				err := configManager.UseOverride(configPath)
				if err != nil {
					r.PrintError(fmt.Sprintf("Failed to read config file: %s\n", err))
					return err
				}
			}

			containers := context.StringSlice("docker")
			for _, container := range containers {
				// TODO: Automatically figure out what docker base image
				// and scan appropriately.
				scanDebianDocker(r, &query, container)
			}

			lockfiles := context.StringSlice("lockfile")
			for _, lockfileElem := range lockfiles {
				lockfileElem, err := filepath.Abs(lockfileElem)
				if err != nil {
					r.PrintError(fmt.Sprintf("Failed to resolved path with error %s\n", err))
					return err
				}
				err = scanLockfile(r, &query, lockfileElem)
				if err != nil {
					return err
				}
			}

			sboms := context.StringSlice("sbom")
			for _, sbomElem := range sboms {
				sbomElem, err := filepath.Abs(sbomElem)
				if err != nil {
					r.PrintError(fmt.Sprintf("Failed to resolved path with error %s\n", err))
					return err
				}
				err = scanSBOMFile(r, &query, sbomElem)
				if err != nil {
					return err
				}
			}

			skipGit := context.Bool("skip-git")
			recursive := context.Bool("recursive")
			genericDirs := context.Args().Slice()
			for _, dir := range genericDirs {
				r.PrintText(fmt.Sprintf("Scanning dir %s\n", dir))
				err := scanDir(r, &query, dir, skipGit, recursive)
				if err != nil {
					return err
				}
			}

			if len(query.Queries) == 0 {
				_ = cli.ShowAppHelp(context)
				return fmt.Errorf("")
			}

			return nil
		},
	}

	if err := app.Run(args); err != nil {
		r.PrintError(fmt.Sprintf("%v", err))
		return 1
	}

	resp, err := osv.MakeRequest(query)
	if err != nil {
		r.PrintError(fmt.Sprintf("Scan failed: %v", err))
		return 1
	}

	filtered := filterResponse(r, query, resp, &configManager)
	if filtered > 0 {
		r.PrintText(fmt.Sprintf("Filtered %d vulnerabilities from output\n", filtered))
	}

	hydratedResp, err := osv.Hydrate(resp)
	if err != nil {
		r.PrintError(fmt.Sprintf("Failed to hydrate OSV response: %v", err))
		return 1
	}

	err = r.PrintResult(query, hydratedResp)

	if err != nil {
		r.PrintError(fmt.Sprintf("Failed to write output: %s", err))
		return 1
	}

	return 0
}

// TODO(ochang): Machine readable output format.
func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}
