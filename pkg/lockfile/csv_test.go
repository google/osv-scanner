package lockfile_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestFromCSVRows(t *testing.T) {
	t.Parallel()

	type args struct {
		filePath string
		parseAs  string
		rows     []string
	}
	tests := []struct {
		name string
		args args
		want lockfile.Lockfile
	}{
		{
			name: "",
			args: args{
				filePath: "-",
				parseAs:  "-",
				rows:     nil,
			},
			want: lockfile.Lockfile{
				FilePath: "-",
				ParsedAs: "-",
				Packages: nil,
			},
		},
		{
			name: "",
			args: args{
				filePath: "-",
				parseAs:  "csv-row",
				rows: []string{
					"crates.io,,addr2line,0.15.2",
					"npm,,@typescript-eslint/types,5.13.0",
					"crates.io,,wasi,0.10.2+wasi-snapshot-preview1",
					"Packagist,,sentry/sdk,2.0.4",
				},
			},
			want: lockfile.Lockfile{
				FilePath: "-",
				ParsedAs: "csv-row",
				Packages: []lockfile.PackageDetails{
					{
						Name:      "@typescript-eslint/types",
						Version:   "5.13.0",
						Ecosystem: lockfile.PnpmEcosystem,
						CompareAs: lockfile.PnpmEcosystem,
					},
					{
						Name:      "addr2line",
						Version:   "0.15.2",
						Ecosystem: lockfile.CargoEcosystem,
						CompareAs: lockfile.CargoEcosystem,
					},
					{
						Name:      "sentry/sdk",
						Version:   "2.0.4",
						Ecosystem: lockfile.ComposerEcosystem,
						CompareAs: lockfile.ComposerEcosystem,
					},
					{
						Name:      "wasi",
						Version:   "0.10.2+wasi-snapshot-preview1",
						Ecosystem: lockfile.CargoEcosystem,
						CompareAs: lockfile.CargoEcosystem,
					},
				},
			},
		},
		{
			name: "",
			args: args{
				filePath: "-",
				parseAs:  "-",
				rows: []string{
					"NuGet,,Yarp.ReverseProxy,",
					"npm,,@typescript-eslint/types,5.13.0",
				},
			},
			want: lockfile.Lockfile{
				FilePath: "-",
				ParsedAs: "-",
				Packages: []lockfile.PackageDetails{
					{
						Name:      "@typescript-eslint/types",
						Version:   "5.13.0",
						Ecosystem: lockfile.PnpmEcosystem,
						CompareAs: lockfile.PnpmEcosystem,
					},
					{
						Name:      "Yarp.ReverseProxy",
						Version:   "",
						Ecosystem: "NuGet",
						CompareAs: "NuGet",
					},
				},
			},
		},
		{
			name: "",
			args: args{
				filePath: "-",
				parseAs:  "-",
				rows: []string{
					"NuGet,,Yarp.ReverseProxy,",
					",,vue,bb253db0b3e17124b6d1fe93fbf2db35470a1347",
				},
			},
			want: lockfile.Lockfile{
				FilePath: "-",
				ParsedAs: "-",
				Packages: []lockfile.PackageDetails{
					{
						Name:      "Yarp.ReverseProxy",
						Version:   "",
						Ecosystem: "NuGet",
						CompareAs: "NuGet",
					},
					{
						Name:      "vue",
						Version:   "",
						Ecosystem: "",
						CompareAs: "",
						Commit:    "bb253db0b3e17124b6d1fe93fbf2db35470a1347",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := lockfile.FromCSVRows(tt.args.filePath, tt.args.parseAs, tt.args.rows)
			if err != nil {
				t.Errorf("FromCSVFile() error = %v, was not expected", err)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromCSVRows() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromCSVRows_Errors(t *testing.T) {
	t.Parallel()

	type args struct {
		filePath string
		parseAs  string
		rows     []string
	}
	tests := []struct {
		name       string
		args       args
		wantErrMsg string
	}{
		{
			name: "",
			args: args{
				filePath: "",
				parseAs:  "",
				rows:     []string{"one,,,"},
			},
			wantErrMsg: "row 1: field 3 is empty (must be the name of a package)",
		},
		{
			name: "",
			args: args{
				filePath: "",
				parseAs:  "",
				rows: []string{
					"crates.io,,addr2line,",
					",,,",
				},
			},
			wantErrMsg: "row 2: field 4 is empty (must be a commit)",
		},
		{
			name: "",
			args: args{
				filePath: "",
				parseAs:  "",
				rows: []string{
					"crates.io,,addr2line,",
					"npm,,,",
				},
			},
			wantErrMsg: "row 2: field 3 is empty (must be the name of a package)",
		},
		{
			name: "",
			args: args{
				filePath: "",
				parseAs:  "",
				rows: []string{
					"crates.io,,addr2line,",
					",,,,",
				},
			},
			wantErrMsg: "record on line 2: wrong number of fields",
		},
		{
			name: "",
			args: args{
				filePath: "",
				parseAs:  "",
				rows: []string{
					"crates.io,,addr2line,",
					",,,,",
				},
			},
			wantErrMsg: "record on line 2: wrong number of fields",
		},
		{
			name: "",
			args: args{
				filePath: "",
				parseAs:  "",
				rows: []string{
					"NuGet,",
					"npm,,@typescript-eslint/types,5.13.0",
				},
			},
			wantErrMsg: "row 1: not enough fields (expected at least four)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := lockfile.FromCSVRows(tt.args.filePath, tt.args.parseAs, tt.args.rows)

			if err == nil {
				t.Errorf("FromCSVRows() did not error")

				return
			}

			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("FromCSVRows() error = \"%v\", wanted \"%s\"", err, tt.wantErrMsg)
			}
		})
	}
}

func TestFromCSVFile(t *testing.T) {
	t.Parallel()

	type args struct {
		pathToCSV string
		parseAs   string
	}
	tests := []struct {
		name string
		args args
		want lockfile.Lockfile
	}{
		{
			name: "",
			args: args{
				pathToCSV: "fixtures/csv/empty.csv",
				parseAs:   "csv-file",
			},
			want: lockfile.Lockfile{
				FilePath: "fixtures/csv/empty.csv",
				ParsedAs: "csv-file",
				Packages: nil,
			},
		},
		{
			name: "",
			args: args{
				pathToCSV: "fixtures/csv/multiple-rows.csv",
				parseAs:   "csv-file",
			},
			want: lockfile.Lockfile{
				FilePath: "fixtures/csv/multiple-rows.csv",
				ParsedAs: "csv-file",
				Packages: []lockfile.PackageDetails{
					{
						Name:      "@typescript-eslint/types",
						Version:   "4.9.0",
						Ecosystem: lockfile.PnpmEcosystem,
						CompareAs: lockfile.PnpmEcosystem,
					},
					{
						Name:      "@typescript-eslint/types",
						Version:   "5.13.0",
						Ecosystem: lockfile.PnpmEcosystem,
						CompareAs: lockfile.PnpmEcosystem,
					},
					{
						Name:      "addr2line",
						Version:   "0.15.2",
						Ecosystem: lockfile.CargoEcosystem,
						CompareAs: lockfile.CargoEcosystem,
					},
					{
						Name:      "sentry/sdk",
						Version:   "2.0.4",
						Ecosystem: lockfile.ComposerEcosystem,
						CompareAs: lockfile.ComposerEcosystem,
					},
					{
						Name:      "wasi",
						Version:   "0.10.2+wasi-snapshot-preview1",
						Ecosystem: lockfile.CargoEcosystem,
						CompareAs: lockfile.CargoEcosystem,
					},
				},
			},
		},
		{
			name: "",
			args: args{
				pathToCSV: "fixtures/csv/with-extra-columns.csv",
				parseAs:   "csv-file",
			},
			want: lockfile.Lockfile{
				FilePath: "fixtures/csv/with-extra-columns.csv",
				ParsedAs: "csv-file",
				Packages: []lockfile.PackageDetails{
					{
						Name:      "@typescript-eslint/types",
						Version:   "5.13.0",
						Ecosystem: lockfile.PnpmEcosystem,
						CompareAs: lockfile.PnpmEcosystem,
					},
					{
						Name:      "addr2line",
						Version:   "0.15.2",
						Ecosystem: lockfile.CargoEcosystem,
						CompareAs: lockfile.CargoEcosystem,
					},
					{
						Name:      "sentry/sdk",
						Version:   "2.0.4",
						Ecosystem: lockfile.ComposerEcosystem,
						CompareAs: lockfile.ComposerEcosystem,
					},
					{
						Name:      "wasi",
						Version:   "0.10.2+wasi-snapshot-preview1",
						Ecosystem: lockfile.CargoEcosystem,
						CompareAs: lockfile.CargoEcosystem,
					},
				},
			},
		},
		{
			name: "",
			args: args{
				pathToCSV: "fixtures/csv/one-row.csv",
				parseAs:   "-",
			},
			want: lockfile.Lockfile{
				FilePath: "fixtures/csv/one-row.csv",
				ParsedAs: "-",
				Packages: []lockfile.PackageDetails{
					{
						Name:      "@typescript-eslint/types",
						Version:   "5.13.0",
						Ecosystem: lockfile.PnpmEcosystem,
						CompareAs: "NuGet",
					},
				},
			},
		},
		{
			name: "",
			args: args{
				pathToCSV: "fixtures/csv/two-rows.csv",
				parseAs:   "-",
			},
			want: lockfile.Lockfile{
				FilePath: "fixtures/csv/two-rows.csv",
				ParsedAs: "-",
				Packages: []lockfile.PackageDetails{
					{
						Name:      "@typescript-eslint/types",
						Version:   "5.13.0",
						Ecosystem: lockfile.PnpmEcosystem,
						CompareAs: lockfile.PnpmEcosystem,
					},
					{
						Name:      "Yarp.ReverseProxy",
						Version:   "",
						Ecosystem: "NuGet",
						CompareAs: "NuGet",
					},
				},
			},
		},
		{
			name: "",
			args: args{
				pathToCSV: "fixtures/csv/with-headers.csv",
				parseAs:   "-",
			},
			want: lockfile.Lockfile{
				FilePath: "fixtures/csv/with-headers.csv",
				ParsedAs: "-",
				Packages: []lockfile.PackageDetails{
					{
						Name:      "@typescript-eslint/types",
						Version:   "5.13.0",
						Ecosystem: lockfile.PnpmEcosystem,
						CompareAs: lockfile.PnpmEcosystem,
					},
					{
						Name:      "Package",
						Version:   "Version",
						Ecosystem: "Ecosystem",
						CompareAs: "CompareAs",
					},
					{
						Name:      "sentry/sdk",
						Version:   "2.0.4",
						Ecosystem: lockfile.ComposerEcosystem,
						CompareAs: lockfile.ComposerEcosystem,
					},
				},
			},
		},
		{
			name: "",
			args: args{
				pathToCSV: "fixtures/csv/commits.csv",
				parseAs:   "-",
			},
			want: lockfile.Lockfile{
				FilePath: "fixtures/csv/commits.csv",
				ParsedAs: "-",
				Packages: []lockfile.PackageDetails{
					{
						Name:      "@typescript-eslint/types",
						Version:   "4.9.0",
						Ecosystem: lockfile.PnpmEcosystem,
						CompareAs: lockfile.PnpmEcosystem,
					},
					{
						Name:      "addr2line",
						Version:   "0.15.2",
						Ecosystem: lockfile.CargoEcosystem,
						CompareAs: lockfile.CargoEcosystem,
					},
					{
						Name:      "babel-preset-php",
						Version:   "",
						Ecosystem: "",
						CompareAs: "",
						Commit:    "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
					},
					{
						Name:      "vue",
						Version:   "",
						Ecosystem: "",
						CompareAs: "",
						Commit:    "bb253db0b3e17124b6d1fe93fbf2db35470a1347",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := lockfile.FromCSVFile(tt.args.pathToCSV, tt.args.parseAs)
			if err != nil {
				t.Errorf("FromCSVFile() error = %v, was not expected", err)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromCSVFile() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromCSVFile_Errors(t *testing.T) {
	t.Parallel()

	type args struct {
		pathToCSV string
		parseAs   string
	}
	tests := []struct {
		name       string
		args       args
		wantErrMsg string
	}{
		{
			name: "",
			args: args{
				pathToCSV: "fixtures/csv/does-not-exist",
				parseAs:   "csv-file",
			},
			wantErrMsg: "could not read fixtures/csv/does-not-exist",
		},
		{
			name: "",
			args: args{
				pathToCSV: "fixtures/csv/not-a-csv.xml",
				parseAs:   "csv-file",
			},
			wantErrMsg: "fixtures/csv/not-a-csv.xml: row 1: not enough fields (expected at least four)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := lockfile.FromCSVFile(tt.args.pathToCSV, tt.args.parseAs)

			if err == nil {
				t.Errorf("FromCSVFile() did not error")

				return
			}

			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("FromCSVFile() error = \"%v\", wanted \"%s\"", err, tt.wantErrMsg)
			}
		})
	}
}
