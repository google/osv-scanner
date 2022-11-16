package main

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/osv.dev/tools/osv-scanner/internal/osv"
	"github.com/google/osv.dev/tools/osv-scanner/internal/output"
	"github.com/google/osv.dev/tools/osv-scanner/internal/sbom"
	"github.com/google/osv.dev/tools/osv-scanner/pkg/lockfile"

	"github.com/urfave/cli/v2"
)

const osvScannerConfigName = "osv-scanner.toml"

// scanDir walks through the given directory to try to find any relevant files
// These include:
//   - Any lockfiles with scanLockfile
//   - Any SBOM files with scanSBOMFile
//   - Any git repositories with scanGit
func scanDir(query *osv.BatchedQuery, dir string, skipGit bool, recursive bool) error {
	root := true
	return filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			log.Printf("Failed to walk %s: %v", path, err)
			return err
		}
		path, err = filepath.Abs(path)
		if err != nil {
			log.Fatalf("Failed to walk path %s", err)
		}

		if !skipGit && info.IsDir() && info.Name() == ".git" {
			err := scanGit(query, filepath.Dir(path)+"/")
			if err != nil {
				log.Printf("scan failed for %s: %v\n", path, err)
				return err
			}
			return filepath.SkipDir
		}

		if !info.IsDir() {
			if parser, _ := lockfile.FindParser(path, ""); parser != nil {
				err := scanLockfile(query, path)
				if err != nil {
					log.Println("Attempted to scan lockfile but failed: " + path)
				}
			}
			// No need to check for error
			// If scan fails, it means it isn't a valid SBOM file,
			// so just move onto the next file
			_ = scanSBOMFile(query, path)
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
func scanLockfile(query *osv.BatchedQuery, path string) error {
	parsedLockfile, err := lockfile.Parse(path, "")
	if err != nil {
		return err
	}
	log.Printf("Scanned %s file and found %d packages", path, len(parsedLockfile.Packages))

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
func scanSBOMFile(query *osv.BatchedQuery, path string) error {
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
			log.Printf("Scanned %s SBOM", provider.Name())
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
func scanGit(query *osv.BatchedQuery, repoDir string) error {
	commit, err := getCommitSHA(repoDir)
	if err != nil {
		return err
	}

	log.Printf("Scanning %s at commit %s", repoDir, commit)

	gitQuery := osv.MakeCommitRequest(commit)
	gitQuery.Source = osv.Source{
		Path: repoDir,
		Type: "git",
	}
	query.Queries = append(query.Queries, gitQuery)
	return nil
}

func scanDebianDocker(query *osv.BatchedQuery, dockerImageName string) {
	cmd := exec.Command("docker", "run", "--rm", "--entrypoint", "/usr/bin/dpkg-query", dockerImageName, "-f", "${Package}###${Version}\\n", "-W")
	stdout, err := cmd.StdoutPipe()

	if err != nil {
		log.Fatalf("Failed to get stdout: %s", err)
	}
	err = cmd.Start()
	if err != nil {
		log.Fatalf("Failed to start docker image: %s", err)
	}
	defer cmd.Wait()
	if err != nil {
		log.Fatalf("Failed to run docker: %s", err)
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
			log.Fatalf("Unexpected output from Debian container: \n\n%s", text)
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
	log.Printf("Scanned docker image with %d packages", packages)
}

// Filters response according to config, returns number of responses removed
func filterResponse(query osv.BatchedQuery, resp *osv.BatchedResponse, configManager *ConfigManager) int {
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
		log.Printf("%s has been filtered out because: %s", id, ignoreLine.Reason)
	}

	return len(hiddenVulns)
}

func main() {
	configManager := ConfigManager{
		defaultConfig: Config{},
		configMap:     make(map[string]Config),
	}
	var query osv.BatchedQuery
	var outputJson bool

	app := &cli.App{
		Name:    "osv-scanner",
		Usage:   "scans various mediums for dependencies and matches it against the OSV database",
		Suggest: true,
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

			configPath := context.String("config")
			if configPath != "" {
				err := configManager.UseOverride(configPath)
				if err != nil {
					log.Fatalf("Failed to read config file: %s\n", err)
				}
			}

			containers := context.StringSlice("docker")
			for _, container := range containers {
				// TODO: Automatically figure out what docker base image
				// and scan appropriately.
				scanDebianDocker(&query, container)
			}

			lockfiles := context.StringSlice("lockfile")
			for _, lockfileElem := range lockfiles {
				lockfileElem, err := filepath.Abs(lockfileElem)
				if err != nil {
					log.Fatalf("Failed to resolved path with error %s", err)
				}
				err = scanLockfile(&query, lockfileElem)
				if err != nil {
					return err
				}
			}

			sboms := context.StringSlice("sbom")
			for _, sbomElem := range sboms {
				sbomElem, err := filepath.Abs(sbomElem)
				if err != nil {
					log.Fatalf("Failed to resolved path with error %s", err)
				}
				err = scanSBOMFile(&query, sbomElem)
				if err != nil {
					return err
				}
			}

			skipGit := context.Bool("skip-git")
			recursive := context.Bool("recursive")
			genericDirs := context.Args().Slice()
			for _, dir := range genericDirs {
				log.Printf("Scanning dir %s\n", dir)
				err := scanDir(&query, dir, skipGit, recursive)
				if err != nil {
					return err
				}
			}

			if len(query.Queries) == 0 {
				cli.ShowAppHelpAndExit(context, 1)
			}

			outputJson = context.Bool("json")

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

	resp, err := osv.MakeRequest(query)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	filtered := filterResponse(query, resp, &configManager)
	if filtered > 0 {
		log.Printf("Filtered %d vulnerabilities from output", filtered)
	}

	hydratedResp, err := osv.Hydrate(resp)
	if err != nil {
		log.Fatalf("Failed to hydrate OSV response: %v", err)
	}

	if outputJson {
		err = output.PrintJSONResults(query, hydratedResp, os.Stdout)
	} else {
		output.PrintTableResults(query, hydratedResp, os.Stdout)
	}

	if err != nil {
		log.Fatalf("Failed to write output: %s", err)
	}
}
