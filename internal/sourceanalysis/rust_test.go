package sourceanalysis

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func Test_extractRlibArchive(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("testdata/rust/archives")
	if err != nil {
		t.Error(err)
	}
	for _, file := range entries {
		filename := file.Name()
		t.Run("Extract Rlib "+filename, func(t *testing.T) {
			t.Parallel()
			buf, err := extractRlibArchive(filepath.Join("testdata/rust/archives", filename))
			if err != nil {
				t.Error(err)
			}

			expectedFileName := strings.Replace(filename, ".rlib", ".o", 1)
			expectedBuf, err := os.ReadFile(filepath.Join("testdata/rust/objs", expectedFileName))
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(buf.Bytes(), expectedBuf) {
				t.Fatalf("Extracted not identical to expected: %s", filepath.Join("testdata/rust/archives", filename))
			}
		})
	}
}

func Test_functionsFromDWARF(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("testdata/rust/objs")
	if err != nil {
		t.Error(err)
	}
	for _, file := range entries {
		filename := file.Name()
		t.Run("Parsing DWARF "+filename, func(t *testing.T) {
			t.Parallel()
			buf, err := os.ReadFile(filepath.Join("testdata/rust/objs", filename))
			if err != nil {
				t.Error(err)
			}
			functions, err := functionsFromDWARF(bytes.NewReader(buf))
			if err != nil {
				t.Error(err)
			}

			testutility.NewSnapshot().MatchJSON(t, functions)
		})
	}
}

func Test_rustBuildSource(t *testing.T) {
	testutility.SkipIfNotAcceptanceTesting(t, "Requires rust toolchain to be installed")
	testutility.SkipIfShort(t)

	t.Parallel()

	cwd := testutility.GetCurrentWorkingDirectory(t)

	type args struct {
		source models.SourceInfo
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			args: args{
				source: models.SourceInfo{
					Path: "testdata/rust/rust-project/Cargo.lock",
					Type: "lockfile",
				},
			},
			want: []string{
				cwd + filepath.FromSlash("/testdata/rust/rust-project/target/release/test-project") + testutility.ValueIfOnWindows(".exe", ""),
			},
		},
	}
	for _, tt := range tests {
		got, err := rustBuildSource(tt.args.source)
		if (err != nil) != tt.wantErr {
			t.Errorf("rustBuildSource() error = %v, wantErr %v", err, tt.wantErr)
			return
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("rustBuildSource() = %v, want %v", got, tt.want)
		}
	}
}

// An ar archive with no object file member is not an rlib we can analyse, so it should return
// an error.
func Test_extractRlibArchive_noObjectFile(t *testing.T) {
	t.Parallel()

	// Built by hand so the test needs no `ar` binary on the machine running it.
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	const content = "hi"
	// name[16] mtime[12] uid[6] gid[6] mode[8] size[10] fmag[2]
	fmt.Fprintf(&archive, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", "a.txt/", 0, 0, 0, "100644", len(content))
	archive.WriteString(content)

	path := filepath.Join(t.TempDir(), "not-an-rlib.rlib")
	if err := os.WriteFile(path, archive.Bytes(), 0600); err != nil {
		t.Fatalf("failed to write test archive: %v", err)
	}

	_, err := extractRlibArchive(path)
	if err == nil {
		t.Fatal("expected an error for an ar archive with no object file, got nil")
	}
	if !strings.Contains(err.Error(), "no object file found") {
		t.Errorf("expected a 'no object file found' error, got: %v", err)
	}
}
