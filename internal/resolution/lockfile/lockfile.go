// Package lockfile provides functionality for reading and writing lockfiles.
package lockfile

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/v2/internal/resolution/depfile"
)

type DependencyPatch struct {
	Pkg         resolve.PackageKey
	OrigVersion string
	NewVersion  string
}

type ReadWriter interface {
	// System returns which ecosystem this ReadWriter is for.
	System() resolve.System
	// Read parses a lockfile into a resolved graph
	Read(file depfile.DepFile) (*resolve.Graph, error)
	// Write applies the DependencyPatches to the lockfile, with minimal changes to the file.
	// `original` is the original lockfile to read from. The updated lockfile is written to `output`.
	Write(original depfile.DepFile, output io.Writer, patches []DependencyPatch) error
}

func Overwrite(rw ReadWriter, filename string, patches []DependencyPatch) error {
	r, err := depfile.OpenLocalDepFile(filename)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = rw.Write(r, &buf, patches)
	r.Close() // Make sure the file is closed before we start writing to it.
	if err != nil {
		return err
	}

	//nolint:gosec // Complaining about the 0644 permissions.
	// The file already exists anyway so the permissions don't matter.
	if err := os.WriteFile(filename, buf.Bytes(), 0644); err != nil {
		return err
	}

	return nil
}

func GetReadWriter(pathToLockfile string) (ReadWriter, error) {
	base := filepath.Base(pathToLockfile)
	switch base {
	case "package-lock.json":
		return NpmReadWriter{}, nil
	default:
		return nil, fmt.Errorf("unsupported lockfile type: %s", base)
	}
}
