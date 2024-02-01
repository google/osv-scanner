package sourceanalysis

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/osv-scanner/internal/testutility"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
)

func Test_extractRlibArchive(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("fixtures-rust/archives")
	if err != nil {
		t.Error(err)
	}
	for _, file := range entries {
		filename := file.Name()
		t.Run("Extract Rlib "+filename, func(t *testing.T) {
			t.Parallel()
			buf, err := extractRlibArchive(filepath.Join("fixtures-rust/archives", filename))
			if err != nil {
				t.Error(err)
			}

			expectedFileName := strings.Replace(filename, ".rlib", ".o", 1)
			expectedBuf, err := os.ReadFile(filepath.Join("fixtures-rust/objs", expectedFileName))
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(buf.Bytes(), expectedBuf) {
				t.Fatalf("Extracted not identical to expected: %s", filepath.Join("fixtures-rust/archives", filename))
			}
		})
	}
}

func Test_functionsFromDWARF(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("fixtures-rust/objs")
	if err != nil {
		t.Error(err)
	}
	for _, file := range entries {
		filename := file.Name()
		t.Run("Parsing DWARF "+filename, func(t *testing.T) {
			t.Parallel()
			buf, err := os.ReadFile(filepath.Join("fixtures-rust/objs", filename))
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
	testutility.AcceptanceTests(t, "Requires rust toolchain to be installed")
	t.Parallel()

	workingDir, err := os.Getwd()
	if err != nil {
		t.Error(err)
	}

	type args struct {
		r      reporter.Reporter
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
				r: &reporter.VoidReporter{},
				source: models.SourceInfo{
					Path: "fixtures-rust/rust-project/Cargo.lock",
					Type: "lockfile",
				},
			},
			want: []string{
				workingDir + filepath.FromSlash("/fixtures-rust/rust-project/target/release/test-project") + testutility.ValueIfOnWindows(".exe", ""),
			},
		},
	}
	for _, tt := range tests {
		got, err := rustBuildSource(tt.args.r, tt.args.source)
		if (err != nil) != tt.wantErr {
			t.Errorf("rustBuildSource() error = %v, wantErr %v", err, tt.wantErr)
			return
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("rustBuildSource() = %v, want %v", got, tt.want)
		}
	}
}
