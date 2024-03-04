package lockfile

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/pkg/lockfile"
)

type DependencyPatch struct {
	Pkg         resolve.PackageKey
	OrigVersion string
	NewVersion  string
}

type LockfileIO interface {
	// Read parses a lockfile into a resolved graph
	Read(file lockfile.DepFile) (*resolve.Graph, error)
	// Write applies the DependencyPatches to the lockfile, with minimal changes to the file.
	// `original` is the original lockfile to read from. The updated lockfile is written to `output`.
	Write(original lockfile.DepFile, output io.Writer, patches []DependencyPatch) error
}

func Overwrite(rw LockfileIO, filename string, patches []DependencyPatch) error {
	r, err := lockfile.OpenLocalDepFile(filename)
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

func GetLockfileIO(pathToLockfile string) (LockfileIO, error) {
	base := filepath.Base(pathToLockfile)
	switch {
	case base == "package-lock.json":
		return NpmLockfileIO{}, nil
	default:
		return nil, fmt.Errorf("unsupported lockfile type: %s", base)
	}
}
