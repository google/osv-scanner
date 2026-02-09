package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"deps.dev/util/pypi"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// ModuleInfo represents a Python module or function imported from a library
type ModuleInfo struct {
	Name                 string   // Original name of the imported module/function
	Alias                string   // Alias used in the import statement (if any)
	SourceDefinedPaths   []string // File paths where this module/function is defined in the library source
	ImportedLibraryNames []string // Names of libraries imported in the module's source files
	ReachableDeps        []string // Names of dependencies that are actually used by this module
}

// LibraryInfo represents a Python library and its dependencies
type LibraryInfo struct {
	Name         string        // Library name as it appears in imports
	Alias        string        // Alias used when importing the entire library
	Version      string        // Version from poetry.lock
	Modules      []*ModuleInfo // Specific modules or functions imported from this library
	Dependencies []string      // Direct dependencies declared in library's metadata
}

// safeOpenFile safely opens a file and returns a closer function
func safeOpenFile(filePath string) (*os.File, func(), error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	closer := func() {
		if err := file.Close(); err != nil {
			log.Printf("Error closing file %s: %v", filePath, err)
		}
	}
	return file, closer, nil
}

// scanFile is a helper function that provides a common way to scan files line by line
func scanFile(file io.Reader, processLine func(string) error) error {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if err := processLine(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// getOrCreateLibraryInfo gets an existing library info or creates a new one
func getOrCreateLibraryInfo(libraries map[string]*LibraryInfo, name string) *LibraryInfo {
	lib, found := libraries[name]
	if !found {
		lib = &LibraryInfo{Name: name}
		libraries[name] = lib
	}
	return lib
}

// createMapFromLibraryInfos creates a map of library infos keyed by name
func createMapFromLibraryInfos(libraryInfos []*LibraryInfo) map[string]*LibraryInfo {
	libraries := make(map[string]*LibraryInfo, len(libraryInfos))
	for _, lib := range libraryInfos {
		libraries[lib.Name] = lib
	}
	return libraries
}

// walkPythonFiles walks through a directory and processes only Python files
func walkPythonFiles(root string, processPythonFile func(path string, info os.FileInfo) error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".py") {
			return processPythonFile(path, info)
		}
		return nil
	})
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

const (
	ColorReset  = "\033[0m"
	ColorCyan   = "\033[36m" // For labels
	ColorYellow = "\033[33m" // For values
)

// fileContainsMainEntryPoint checks if a given Python file contains a main entry point.
func fileContainsMainEntryPoint(filePath string) (bool, error) {
	file, closer, err := safeOpenFile(filePath)
	if err != nil {
		return false, err
	}
	defer closer()

	hasMainEntry := false
	err = scanFile(file, func(line string) error {
		if mainEntryRegex.MatchString(line) {
			hasMainEntry = true
			return io.EOF // Stop scanning once we find the main entry
		}
		return nil
	})

	if err == io.EOF {
		return true, nil
	}
	return hasMainEntry, err
}

// findMainEntryPoint scans the target directory for Python files that contain a main entry point.
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

		containsEntry, err := fileContainsMainEntryPoint(path)
		if err != nil {
			return fmt.Errorf("error reading file %s: %w", path, err)
		}

		if containsEntry {
			mainFiles = append(mainFiles, path)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return mainFiles, nil
}

// findManifest searches for supported manifest file in a directory.
func findManifestFiles(dir string) ([]string, error) {
	supportedManifests := []string{"poetry.lock"}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("could not get absolute path for %s: %w", dir, err)
	}
	manifestFiles := []string{}

	files, err := os.ReadDir(absDir)
	if err != nil {
		return nil, fmt.Errorf("could not read directory %s: %w", absDir, err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		fileName := file.Name()
		if slices.Contains(supportedManifests, fileName) {
			manifestFiles = append(manifestFiles, fileName)
		}
	}

	if len(manifestFiles) == 0 {
		return nil, fmt.Errorf("no supported manifest files found in %s", absDir)
	}

	return manifestFiles, nil
}

// parsePoetryLock reads the poetry lock file and updates libraryInfo with versions.
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

// findImportedLibraries scans the Python file for all import statements.
func findImportedLibraries(file io.Reader) ([]*LibraryInfo, error) {
	importedLibraries := make(map[string]*LibraryInfo)

	err := scanFile(file, func(line string) error {
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			return nil
		}

		// Parse import statements without checking poetry.lock
		if match := importRegex.FindStringSubmatch(line); match != nil {
			libraryName := match[1]
			alias := match[2]
			lib := getOrCreateLibraryInfo(importedLibraries, libraryName)
			lib.Alias = alias

		} else if match := fromImportRegex.FindStringSubmatch(line); match != nil {
			libraryName := match[1]
			items := match[2]

			lib := getOrCreateLibraryInfo(importedLibraries, libraryName)
			if strings.TrimSpace(items) == "*" {
				lib.Modules = append(lib.Modules, &ModuleInfo{Name: "*"})
			} else {
				items := strings.Split(items, ",")
				for _, item := range items {
					item = strings.TrimSpace(item)
					if itemMatch := importItemRegex.FindStringSubmatch(item); itemMatch != nil {
						lib.Modules = append(lib.Modules, &ModuleInfo{
							Name:  itemMatch[1],
							Alias: itemMatch[2],
						})
					}
				}
			}
		} else if match := memberImportRegex.FindStringSubmatch(line); match != nil {
			libraryName := match[1]
			moduleName := match[2]

			lib := getOrCreateLibraryInfo(importedLibraries, libraryName)
			lib.Modules = append(lib.Modules, &ModuleInfo{Name: moduleName})
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error scanning file: %w", err)
	}

	fileLibraryInfos := make([]*LibraryInfo, 0, len(importedLibraries))
	for _, lib := range importedLibraries {
		fileLibraryInfos = append(fileLibraryInfos, lib)
	}
	return fileLibraryInfos, nil
}

// findLibrariesPoetryLock scans the Python file for import statements and returns a list of LibraryInfo,
// filtered to only include libraries present in the poetry.lock file.
func findLibrariesPoetryLock(file io.Reader, poetryLibraryInfos []*LibraryInfo) ([]*LibraryInfo, error) {
	// Create a map of poetry libraries for quick lookup
	poetryLibraries := createMapFromLibraryInfos(poetryLibraryInfos)

	// Find all imported libraries first
	allLibraries, err := findImportedLibraries(file)
	if err != nil {
		return nil, err
	}

	// Filter and enrich libraries that are in poetry.lock
	var filteredLibraries []*LibraryInfo
	for _, lib := range allLibraries {
		if poetryLib, ok := poetryLibraries[lib.Name]; ok {
			// Create a new library info with version from poetry.lock
			enrichedLib := &LibraryInfo{
				Name:    poetryLib.Name,
				Version: poetryLib.Version,
				Alias:   lib.Alias,
				Modules: lib.Modules,
			}
			filteredLibraries = append(filteredLibraries, enrichedLib)
		}
	}

	return filteredLibraries, nil
}

// extractCompressedPackageSource extracts a .tar.gz file to a specified destination directory.
func extractCompressedPackageSource(file *os.File) error {
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

// retrieveSourceAndCollectDependencies fetches the source code of a library from PyPI, extracts the compressed source file and
// collect dependencies of the imported library.
func retrieveSourceAndCollectDependencies(ctx context.Context, libraryInfo *LibraryInfo) error {
	reg := datasource.NewPyPIRegistryAPIClient("")
	response, err := reg.GetIndex(ctx, libraryInfo.Name)
	if err != nil {
		return fmt.Errorf("failed to get package info from PyPI: %w", err)
	}

	// Find the source distribution (.tar.gz) file URL
	downloadURL := ""
	fileName := strings.ToLower(fmt.Sprintf(`%s-%s.tar.gz`, libraryInfo.Name, libraryInfo.Version))
	for _, file := range response.Files {
		if file.Name == fileName {
			downloadURL = file.URL
			break
		}
	}

	sourceFile, err := reg.GetFile(ctx, downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download package source: %w", err)
	}

	reader := bytes.NewReader(sourceFile)
	// Open the downloaded file to collect dependencies of the imported library.
	metadata, err := pypi.SdistMetadata(ctx, fileName, reader)
	if err != nil {
		log.Printf("failed to parse metadata from %s: %v", sourceFile, err)
	}
	for _, dep := range metadata.Dependencies {
		libraryInfo.Dependencies = append(libraryInfo.Dependencies, dep.Name)

	}

	tmpFile, err := os.CreateTemp("", "source-*.tar.gz")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()
	defer os.Remove(tmpFile.Name()) // Clean up the temp file after extraction

	_, err = io.Copy(tmpFile, reader)
	if err != nil {
		return fmt.Errorf("failed to write to temp file: %w", err)
	}
	err = extractCompressedPackageSource(tmpFile)
	if err != nil {
		return err
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

	return walkPythonFiles(libraryFolder, func(path string, _ os.FileInfo) error {
		file, closer, err := safeOpenFile(path)
		if err != nil {
			return err
		}
		defer closer()

		return scanFile(file, func(line string) error {
			for _, module := range libraryInfo.Modules {
				searchTerm := fmt.Sprintf("def %s(", module.Name)
				if strings.Contains(line, searchTerm) {
					module.SourceDefinedPaths = append(module.SourceDefinedPaths, path)
				}
			}
			return nil
		})
	})
}

// findImportedItemPaths finds libraries in import statements in the files.
func findImportedLibrary(libraryInfo *LibraryInfo) error {
	for _, module := range libraryInfo.Modules {
		for _, path := range module.SourceDefinedPaths {
			absPath, err := filepath.Abs(path)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for %s: %w", path, err)
			}
			file, err := os.Open(absPath)
			if err != nil {
				return fmt.Errorf("failed to open file %s: %w", path, err)
			}
			defer file.Close()

			importedLibraries, err := findImportedLibraries(file)
			if err != nil {
				return fmt.Errorf("failed to find libraries in file %s: %w", path, err)
			}

			for _, lib := range importedLibraries {
				module.ImportedLibraryNames = append(module.ImportedLibraryNames, lib.Name)
			}
		}
	}

	return nil
}

func main() {
	flag.Parse()
	ctx := context.Background()

	// Check if the flag was actually set by the user.
	fileFlagProvided := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "directory" {
			fileFlagProvided = true
		}
	})
	if !fileFlagProvided {
		fmt.Fprintln(os.Stderr, "Error: -directory flag is required.")
		flag.Usage()
		return
	}

	// 1. Looking for files with main entry point
	pythonFiles, err := findMainEntryPoint(*directory)
	if err != nil {
		log.Printf("Error finding main entry point: %v\n", err)
	}

	if len(pythonFiles) == 0 {
		log.Println("No Python files with a main entry point found.")
		return
	}

	// 2. Collect libraries from supported manifest files.
	manifestFiles, err := findManifestFiles(*directory)
	if err != nil {
		log.Printf("Error finding manifest files: %v\n", err)
		return
	}

	poetryLibraryInfos := []*LibraryInfo{}
	for _, manifestFile := range manifestFiles {
		switch manifestFile {
		case "poetry.lock":
			// Parse the poetry.lock file to get library information.
			poetryLibraryInfos, err = parsePoetryLock(ctx, filepath.Join(*directory))
			if err != nil {
				log.Printf("Error collecting libraries in poetry.lock: %v\n", err)
			}
		}
	}

	for _, file := range pythonFiles {
		pythonFile, err := os.Open(file)
		if err != nil {
			log.Printf("Error opening Python file %s: %v\n", file, err)
			continue
		}
		defer pythonFile.Close()
		fmt.Printf("Processing Python file: %s\n", pythonFile.Name())
		// 3. Find libraries imported in the main file that are defined in poetry.lock
		importedLibraries, err := findLibrariesPoetryLock(pythonFile, poetryLibraryInfos)
		if err != nil {
			log.Printf("Error finding libraries in file %s: %v\n", file, err)
		}

		// 4. Download the source code of the libraries & collect the dependencies of the libraries.
		for _, lib := range importedLibraries {
			if lib.Version == "" {
				continue
			}
			err = retrieveSourceAndCollectDependencies(ctx, lib)
			if err != nil {
				log.Printf("Get source of lib error: %v\n", err)
			}
		}

		// 5. Traverse directory of the source code and look for Python files where they define the imported items
		// and collect the imported libraries in those files
		for _, lib := range importedLibraries {
			if lib.Version == "" || len(lib.Modules) == 0 {
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

		// 6. Comparison between the collected imported libraries and the PYPI dependencies of the libraries
		// to find the reachability of the PYPI dependencies.
		for _, library := range importedLibraries {
			fmt.Printf("%sLibrary:%s %s%s%s, %sVersion:%s %s%s%s\n",
				ColorCyan, ColorReset,
				ColorYellow,
				library.Name,
				ColorReset,
				ColorCyan, ColorReset,
				ColorYellow,
				library.Version,
				ColorReset)
			if len(library.Modules) == 0 {
				for _, dep := range library.Dependencies {
					fmt.Printf("  %sPyPI Dependencies:%s %s%s%s --> Reachable\n", ColorCyan, ColorReset, ColorYellow, dep, ColorReset)
				}
				continue
			}

			for _, module := range library.Modules {
				if module.SourceDefinedPaths == nil {
					for _, dep := range library.Dependencies {
						fmt.Printf("  %sPyPI Dependencies:%s %s%s%s --> Reachable\n", ColorCyan, ColorReset, ColorYellow, dep, ColorReset)
					}
					continue
				}
				fmt.Printf("  %sImported Item:%s %s%s%s\n", ColorCyan, ColorReset, ColorYellow, module.Name, ColorReset)
				for _, dep := range library.Dependencies {
					fmt.Printf("  %sPyPI Dependencies:%s %s%s%s\n", ColorCyan, ColorReset, ColorYellow, dep, ColorReset)
				}
				fmt.Println("Reachability:")
				for _, dep := range library.Dependencies {
					reachable := false
					slices.Sort(module.ImportedLibraryNames)
					importedLibs := slices.Compact(module.ImportedLibraryNames)
					for _, importedLib := range importedLibs {
						if strings.Contains(importedLib, dep) {
							module.ReachableDeps = append(module.ReachableDeps, dep)
							reachable = true
							break
						}

					}

					if !reachable {
						fmt.Printf("   %sPyPI Dependencies:%s %s%s%s --> Unreachable\n", ColorCyan, ColorReset, ColorYellow, dep, ColorReset)
					} else {
						fmt.Printf("   %sPyPI Dependencies:%s %s%s%s --> Reachable\n", ColorCyan, ColorReset, ColorYellow, dep, ColorReset)
					}
				}
			}
		}

	}
}
