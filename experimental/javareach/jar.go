package javareach

import (
	"archive/zip"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"golang.org/x/sync/errgroup"
)

const (
	maxGoroutines = 4
)

var (
	ErrClassNotFound = errors.New("class not found")
)

// MavenPackageFinder is an interface for finding Maven packages that contain a
// class path.
type MavenPackageFinder interface {
	// Find returns a list of package names that contain a class path.
	Find(classPath string) ([]string, error)
}

// DefaultPackageFinder implements a MavenPackageFinder that downloads all .jar
// dependencies on demand and computes a local class to jar mapping.
type DefaultPackageFinder struct {
	classMap map[string][]string
}

// ExtractDependencies extracts Maven dependencies from a .jar.
func ExtractDependencies(jar *os.File) ([]*extractor.Inventory, error) {
	info, err := jar.Stat()
	if err != nil {
		return nil, err
	}
	input := filesystem.ScanInput{Path: info.Name(), Info: info, Reader: jar}
	cfg := archive.DefaultConfig()
	extractor := archive.New(cfg)
	return extractor.Extract(context.Background(), &input)
}

// extractClassMappings extracts class mappings from a .jar dependency by
// downloading and unpacking the .jar from the relevant registry.
func extractClassMappings(inv *extractor.Inventory, classMap map[string][]string, lock *sync.Mutex) error {
	metadata := inv.Metadata.(*archive.Metadata)
	// TODO: Handle Non-Maven central repositories.
	jarURL := fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar",
		strings.ReplaceAll(metadata.GroupID, ".", "/"), metadata.ArtifactID, inv.Version, metadata.ArtifactID, inv.Version)

	file, err := os.CreateTemp("", "")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()

	slog.Debug("downloading", "jar", jarURL)
	resp, err := http.Get(jarURL)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jar not found: %s", jarURL)
	}

	nbytes, err := io.Copy(file, resp.Body)
	if err != nil {
		resp.Body.Close()
		return err
	}
	resp.Body.Close()

	file.Seek(0, os.SEEK_SET)
	reader, err := zip.NewReader(file, nbytes)
	if err != nil {
		return err
	}

	// TODO: Validate that we can rely on the directory structure to mirror the
	// class package path.
	lock.Lock()
	for _, f := range reader.File {
		if strings.HasSuffix(f.Name, ".class") {
			name := strings.TrimSuffix(f.Name, ".class")
			classMap[name] = append(classMap[name],
				fmt.Sprintf("%s:%s", metadata.GroupID, metadata.ArtifactID))
			slog.Debug("mapping", "name", name, "to", classMap[name])
		}
	}
	lock.Unlock()
	return nil
}

// NewDefaultPackageFinder creates a new DefaultPackageFinder based on a set of
// inventory.
func NewDefaultPackageFinder(inv []*extractor.Inventory) (*DefaultPackageFinder, error) {
	// Download pkg, unpack, and store class mappings for each detected dependency.
	classMap := map[string][]string{}
	lock := new(sync.Mutex)
	group := new(errgroup.Group)
	group.SetLimit(maxGoroutines)

	for _, i := range inv {
		group.Go(func() error {
			return extractClassMappings(i, classMap, lock)
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	return &DefaultPackageFinder{
		classMap: classMap,
	}, nil
}

// Find returns a list of package names that contain a class path.
func (f *DefaultPackageFinder) Find(classPath string) ([]string, error) {
	if pkg, ok := f.classMap[classPath]; ok {
		return pkg, nil
	}

	return nil, ErrClassNotFound
}

// GetMainClass extracts the main class name from the MANIFEST.MF file in a .jar.
func GetMainClass(manifest io.Reader) (string, error) {
	// Extract the Main-Class specified in MANIFEST.MF:
	// https://docs.oracle.com/javase/tutorial/deployment/jar/appman.html
	const mainClass = "Main-Class:"
	scanner := bufio.NewScanner(manifest)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, mainClass) {
			mainClass := strings.TrimSpace(strings.TrimPrefix(line, mainClass))
			return strings.ReplaceAll(mainClass, ".", "/"), nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", errors.New("no main class")
}
