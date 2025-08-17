package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

type ModuleInfo struct {
	Name                  string
	Alias                 string
	DefinitionPaths       []string            // Paths where this item is defined in the library's source code.
	DependenciesByPath    map[string][]string // map[path][]imported_items
	ReachableDependencies []string            // Reachability status of the imported items.
}

type LibraryInfo struct {
	Name             string
	Alias            string
	Version          string
	ImportedItems    []*ModuleInfo
	PyPIDependencies []string
	ItemDependencies map[string][]string //map[imported_item_name][]library_names]
}

type PyPIResponse struct {
	Info struct {
		RequiresDist    []string `json:"requires_dist"`
		Vulnerabilities []string `json:"vulnerabilities"`
	} `json:"info"`
}

type Response struct {
	ImportedLibrary string   `json:"imported_library"`
	UsedModule      []string `json:"used_module"`
}

var (
	directory = flag.String("directory", "directory", "directory to scan")
	// TODO: Find alternative ways for these regexes.
	mainEntryRegex    = regexp.MustCompile(`^\s*if\s+__name__\s*==\s*['"]__main__['"]\s*:`)
	importRegex       = regexp.MustCompile(`^\s*import\s+([a-zA-Z0-9_.]+)(?:\s+as\s+([a-zA-Z0-9_]+))?`)
	fromImportRegex   = regexp.MustCompile(`^\s*from\s+([a-zA-Z0-9_.]+)\s+import\s+(.+)`)
	importItemRegex   = regexp.MustCompile(`([a-zA-Z0-9_.*]+)(?:\s+as\s+([a-zA-Z0-9_]+))?`)
	memberImportRegex = regexp.MustCompile(`import (\w+)\.(\w+)`)
)

// findMainEntryPoint scans the directory for Python files that contain a main entry point.
func findMainEntryPoint(dir string) ([]string, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("could not get absolute path for %s: %w", dir, err)
	}
	mainFiles := []string{}

	err = filepath.WalkDir(absDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".py") {
			return nil
		}

		err = func() error {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				// Check for the main entry point
				if mainEntryRegex.MatchString(line) {
					mainFiles = append(mainFiles, path)
					break // Found it, no need to scan the rest of the file.
				}
			}
			return scanner.Err()
		}()
		if err != nil {
			return fmt.Errorf("error reading file %s: %w", path, err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return mainFiles, nil
}

// parsePoetryLock reads the poetry lock file and updates  libraryInfo with versions.
func parsePoetryLock(ctx context.Context, fpath string) ([]*LibraryInfo, error) {
	dir := filepath.Dir(fpath)
	fsys := scalibrfs.DirFS(dir)
	r, err := fsys.Open("poetry.lock")
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", fpath, err)
	}
	defer r.Close()

	input := &filesystem.ScanInput{
		FS:     fsys,
		Path:   fpath,
		Reader: r,
	}
	extractor := poetrylock.New()
	inventory, err := extractor.Extract(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to extract from %s: %w", fpath, err)
	}

	libraryInfos := []*LibraryInfo{}
	for _, i := range inventory.Packages {
		libraryInfos = append(libraryInfos, &LibraryInfo{Name: i.Name, Version: i.Version})
	}

	return libraryInfos, nil
}

// libraryFinder scans the Python file for import statements and returns a list of LibraryInfo.
func libraryFinder(file *os.File, poetryLibraryInfos []*LibraryInfo) ([]*LibraryInfo, error) {
	poetryLibraries := make(map[string]*LibraryInfo, len(poetryLibraryInfos))
	for _, lib := range poetryLibraryInfos {
		poetryLibraries[lib.Name] = lib
	}
	importedLibraries := make(map[string]*LibraryInfo)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// If the import statement matches, the imported library is in poetry lock file and the imported library is not already in the importedLibraries map,
		// extract the imported library name, version and alias if any.
		if match := importRegex.FindStringSubmatch(line); match != nil {
			libraryName := match[1]
			alias := match[2]

			if lib, ok := poetryLibraries[libraryName]; ok {
				if _, found := importedLibraries[libraryName]; !found {
					importedLibraries[libraryName] = &LibraryInfo{
						Name:    lib.Name,
						Version: lib.Version,
						Alias:   alias,
					}
				}
			}
		} else if match := fromImportRegex.FindStringSubmatch(line); match != nil {
			libraryName := match[1]
			items := match[2]

			if lib, ok := poetryLibraries[libraryName]; ok {
				libraryInfo, found := importedLibraries[libraryName]
				if !found {
					libraryInfo = &LibraryInfo{Name: libraryName, Version: lib.Version}
					importedLibraries[libraryName] = libraryInfo
				}

				if strings.TrimSpace(items) == "*" {
					libraryInfo.ImportedItems = append(libraryInfo.ImportedItems, &ModuleInfo{Name: "*"})
				} else {
					items := strings.Split(items, ",")
					for _, item := range items {
						item = strings.TrimSpace(item)
						if itemMatch := importItemRegex.FindStringSubmatch(item); itemMatch != nil {
							libraryInfo.ImportedItems = append(libraryInfo.ImportedItems, &ModuleInfo{
								Name:  itemMatch[1],
								Alias: itemMatch[2],
							})
						}
					}
				}
				importedLibraries[libraryName] = libraryInfo
			}
		} else if match := memberImportRegex.FindStringSubmatch(line); match != nil {
			libraryName := match[1]
			moduleName := match[2]
			if lib, ok := poetryLibraries[libraryName]; ok {
				if _, found := importedLibraries[libraryName]; !found {
					importedLibraries[libraryName] = &LibraryInfo{
						Name:    lib.Name,
						Version: lib.Version,
					}
				}
				importedLibraries[libraryName].ImportedItems = append(importedLibraries[libraryName].ImportedItems, &ModuleInfo{Name: moduleName})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning file: %w", err)
	}

	fileLibraryInfos := make([]*LibraryInfo, 0, len(importedLibraries))
	for _, lib := range importedLibraries {
		fileLibraryInfos = append(fileLibraryInfos, lib)
	}
	return fileLibraryInfos, nil
}

// getPackageDependencies gets the name of direct dependencies of each library from PyPI and updates the libraryInfo.
func getPackageDependencies(libraryInfos []*LibraryInfo) []error {
	var wg sync.WaitGroup
	errs := make(chan error, len(libraryInfos))

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	for _, library := range libraryInfos {
		if library.Version == "" {
			continue // Skip modules without a version
		}
		wg.Add(1)

		// Use goroutine for each library to fetch dependencies concurrently.
		go func(library *LibraryInfo) {
			defer wg.Done()
			url := fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", library.Name, library.Version)
			resp, err := client.Get(url)
			if err != nil {
				errs <- fmt.Errorf("error fetching package info of url %s: %w", url, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("error fetching package info of url %s: %w", url, err)
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errs <- fmt.Errorf("failed to read body for %s: %w", library.Name, err)
				return
			}

			var pypiResponse PyPIResponse
			err = json.Unmarshal(body, &pypiResponse)
			if err != nil {
				errs <- fmt.Errorf("failed to unmarshal json for %s: %w", library.Name, err)
				return
			}

			requiresDist := pypiResponse.Info.RequiresDist
			for _, dep := range requiresDist {
				re := regexp.MustCompile(`^[^<>=~!]+`)
				matches := re.FindStringSubmatch(dep)
				for _, match := range matches {
					if slices.Contains(library.PyPIDependencies, strings.TrimSpace(match)) {
						continue
					}
					library.PyPIDependencies = append(library.PyPIDependencies, strings.TrimSpace(match))
				}
			}
		}(library)
	}

	wg.Wait()
	close(errs)
	var errSlice []error
	for err := range errs {
		errSlice = append(errSlice, err)
	}
	if len(errSlice) > 0 {
		return errSlice
	}

	return nil
}

// downloadPackageSource downloads the source code of a package from PyPI.
func downloadPackageSource(downloadLink string) (string, error) {
	filename := filepath.Base(downloadLink)
	tempFile, err := os.CreateTemp(".", filename)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tempFile.Close()

	// Get the HTTP response
	resp, err := http.Get(downloadLink)
	if err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to get URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to copy: %w", err)
	}

	fmt.Printf("Downloaded %s to %s\n", filename, tempFile.Name())
	return tempFile.Name(), nil
}

// extractCompressedPackageSource extracts a .tar.gz file to a specified destination directory.
func extractCompressedPackageSource(sourceFile string) error {
	file, err := os.Open(sourceFile)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", sourceFile, err)
	}
	defer file.Close()

	// Create a gzip reader to decompress the stream
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}
		targetPath := filepath.Join(".", header.Name)

		// Handle different file types (directories, regular files)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			// Create the parent directory if it doesn't exist
			parentDir := filepath.Dir(targetPath)
			if err := os.MkdirAll(parentDir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", parentDir, err)
			}

			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to copy content to file %s: %w", targetPath, err)
			}
			outFile.Close()

			// Set file permissions
			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to set permissions on %s: %w", targetPath, err)
			}
		default:
			continue
		}
	}

	return nil
}

// retrievePackageSource fetches the source code of a library from PyPI and extracts it.
func retrievePackageSource(libraryInfo *LibraryInfo) error {
	url := fmt.Sprintf("https://pypi.org/simple/%s/", libraryInfo.Name)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s HTTP error: %d", libraryInfo.Name, resp.StatusCode)
	}

	s := strings.ToLower(fmt.Sprintf(`%s\-%s\.tar\.gz`, libraryInfo.Name, libraryInfo.Version))
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		re := regexp.MustCompile(s)
		matches := re.MatchString(line)
		if matches {
			re = regexp.MustCompile(`<a href="([^"]+)"`)
			substring := re.FindStringSubmatch(line)
			fileName, err := downloadPackageSource(substring[1])
			if err != nil {
				return fmt.Errorf("failed to download package source: %w", err)
			}
			err = extractCompressedPackageSource(fileName)
			if err != nil {
				return err
			}
			err = os.Remove(fileName)
			if err != nil {
				return fmt.Errorf("failed to remove file: %w", err)
			}
			return nil
		}
	}

	return nil
}

// findFolder looks for a folder with the specified name in the given root directory.
func findFolder(root, folderName string) (string, error) {
	var name string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.Contains(d.Name(), folderName) {
			name = d.Name()
			return filepath.SkipAll
		}
		return nil
	})

	if err != nil {
		return "", err
	}
	return name, nil
}

// getImportedItemsFilePaths finds the paths of the files where the imported items are defined.
// It traverses the library directory and checks each Python file for definitions of the imported items.
func getImportedItemsFilePaths(libraryInfo *LibraryInfo) error {
	libraryFolder, err := findFolder(".", fmt.Sprintf("%s-%s", libraryInfo.Name, libraryInfo.Version))
	if err != nil {
		return err
	}

	// Traverse the directories of the library.
	err = filepath.Walk(libraryFolder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if strings.HasSuffix(path, ".py") {
				file, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("failed to open file %s: %w", path, err)
				}
				defer file.Close()

				// Check if the file contains definitions of the imported items.
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					for _, item := range libraryInfo.ImportedItems {
						searchTerm := fmt.Sprintf("def %s(", item.Name)
						if strings.Contains(scanner.Text(), searchTerm) {
							item.DefinitionPaths = append(item.DefinitionPaths, path)
						}
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking through directory %s: %w", libraryFolder, err)
	}
	return nil
}

// findImportedItemPaths finds libraries in import statements in the files where the imported items are defined.
func findImportedLibrary(libraryInfo *LibraryInfo) error {
	for _, item := range libraryInfo.ImportedItems {
		for _, path := range item.DefinitionPaths {
			var importedItems []string
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("failed to open file %s: %w", path, err)
			}
			defer file.Close()

			importedLibraries, err := libraryFinder(file, nil)
			if err != nil {
				return fmt.Errorf("failed to find libraries in file %s: %w", path, err)
			}

			for _, lib := range importedLibraries {
				importedItems = append(importedItems, lib.Name)
			}

			if item.DependenciesByPath == nil {
				item.DependenciesByPath = make(map[string][]string)
			}
			item.DependenciesByPath[path] = importedItems
		}
	}

	return nil
}

func main() {
	flag.Parse()
	ctx := context.Background()

	// 1. Looking for files with main entry point
	pythonFiles, err := findMainEntryPoint(*directory)
	if err != nil {
		log.Printf("Error finding main entry point: %v\n", err)
	}

	for _, file := range pythonFiles {
		// 2. Collect libraries from poertry.lock file
		poetryLibraryInfos, err := parsePoetryLock(ctx, filepath.Join(filepath.Dir(file), "poetry.lock"))
		if err != nil {
			log.Printf("Error collecting libraries in poetry.lock: %v\n", err)
			continue
		}

		pythonFile, err := os.Open(file)
		if err != nil {
			log.Printf("Error opening Python file %s: %v\n", file, err)
			continue
		}
		defer pythonFile.Close()

		// 3. Find libraries imported in the main file that are defined in poetry.lock
		importedLibraries, err := libraryFinder(pythonFile, poetryLibraryInfos)
		if err != nil {
			log.Printf("Error finding libraries in file %s: %v\n", file, err)
		}

		// 4. Get dependencies of the imported libraries
		errs := getPackageDependencies(importedLibraries)
		if len(errs) > 0 {
			for _, err := range errs {
				log.Printf("Error getting package dependencies: %v\n", err)
			}
		}
		// 5. Download the source code of the libraries
		for _, lib := range importedLibraries {
			if lib.Version == "" {
				continue
			}
			err = retrievePackageSource(lib)
			if err != nil {
				log.Printf("Get source of lib error: %v\n", err)
			}
		}

		// 6. Traverse directory of the source code and look for Python files where they define the imported items
		// and collect the imported libraries in those files
		for _, lib := range importedLibraries {
			if lib.Version == "" || len(lib.ImportedItems) == 0 {
				continue
			}
			err := getImportedItemsFilePaths(lib)
			if err != nil {
				log.Printf("get imported items file paths error: %v\n", err)
			}

			// Find the imported libraries in the files where the imported items are defined.
			err = findImportedLibrary(lib)
			if err != nil {
				log.Printf("Error finding imported items: %v\n", err)
			}
		}

		// 7. Comparison between the collected imported libraries and the PYPI dependencies of the libraries
		// to find the reachability of the PYPI dependencies.
		for _, library := range importedLibraries {
			for _, item := range library.ImportedItems {
				if len(item.DefinitionPaths) == 0 {
					fmt.Printf("No paths found for item %s in library %s\n", item.Name, library.Name)
					continue
				}
				for _, importedItems := range item.DependenciesByPath {
					var matchingItems []string
					for _, dep := range library.PyPIDependencies {
						for _, itemName := range importedItems {
							if strings.Contains(itemName, dep) {
								matchingItems = append(matchingItems, itemName)
							}
						}
					}
					if len(matchingItems) > 0 {
						item.ReachableDependencies = matchingItems
					}
				}
			}
		}

	}
}
