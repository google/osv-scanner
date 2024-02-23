package image

import (
	"archive/tar"
	"io"
	"path/filepath"
)

// TarVisitor runs visitor function over every file/directory
func TarVisitor(dist string, visitor func(*tar.Header, io.Reader) error, r io.Reader) error {

	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()
		header.Name = filepath.Clean(header.Name)
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		}

		err = visitor(header, tr)
		if err != nil {
			return err
		}
	}
}
