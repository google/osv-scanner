package lockfile_test

import (
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/google/osv-scanner/pkg/lockfile"
)

func TestParseSetupPy(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/simple/setup.py"))
	packages, err := lockfile.ParseSetupPy(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "Jinja2",
			Version:        "~=2.7.2",
			PackageManager: models.Requirements,
			Ecosystem:      lockfile.PipEcosystem,
			CompareAs:      lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 6, End: 19},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 6, End: 12},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 12, End: 19},
				Filename: path,
			},
		},
		{
			Name:           "Django",
			Version:        ">=1.6.1",
			PackageManager: models.Requirements,
			Ecosystem:      lockfile.PipEcosystem,
			CompareAs:      lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 6, End: 19},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 6, End: 12},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 12, End: 19},
				Filename: path,
			},
		},
		{
			Name:           "python-etcd",
			Version:        "<=0.4.5",
			PackageManager: models.Requirements,
			Ecosystem:      lockfile.PipEcosystem,
			CompareAs:      lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 6, End: 24},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 6, End: 17},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 17, End: 24},
				Filename: path,
			},
		},
		{
			Name:           "Django-Select2",
			Version:        ">6.0.1",
			PackageManager: models.Requirements,
			Ecosystem:      lockfile.PipEcosystem,
			CompareAs:      lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 6, End: 26},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 6, End: 20},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 20, End: 26},
				Filename: path,
			},
		},
		{
			Name:           "irc",
			Version:        "<16.2",
			PackageManager: models.Requirements,
			Ecosystem:      lockfile.PipEcosystem,
			CompareAs:      lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 6, End: 14},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 6, End: 9},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 9, End: 14},
				Filename: path,
			},
		},
		{
			Name:           "testtools",
			Version:        "===2.3.0",
			PackageManager: models.Requirements,
			Ecosystem:      lockfile.PipEcosystem,
			CompareAs:      lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 6, End: 23},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 6, End: 15},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 15, End: 23},
				Filename: path,
			},
		},
		{
			Name:           "requests",
			Version:        "!=2.3.0",
			PackageManager: models.Requirements,
			Ecosystem:      lockfile.PipEcosystem,
			CompareAs:      lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 6, End: 21},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 6, End: 14},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 14, End: 21},
				Filename: path,
			},
		},
		{
			Name:           "tensorflow",
			Version:        "==2.17.0",
			PackageManager: models.Requirements,
			Ecosystem:      lockfile.PipEcosystem,
			CompareAs:      lockfile.PipEcosystem,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 6, End: 24},
				Filename: path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 6, End: 16},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 16, End: 24},
				Filename: path,
			},
		},
	})
}

func TestParseSetupPy_MissingInstallRequiresInsideComment(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/install_requires_comment/setup.py"))
	_, err = lockfile.ParseSetupPy(path)

	assert.ErrorContains(t, err, io.EOF.Error())
}

func TestParseSetupPy_UnexpectedEoF(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/unexpected_eof/setup.py"))
	_, err = lockfile.ParseSetupPy(path)

	assert.ErrorContains(t, err, "unexpected text=)\n")
}

func TestParseSetupPy_DoubleEqual(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/double_equals/setup.py"))
	_, err = lockfile.ParseSetupPy(path)

	assert.ErrorContains(t, err, "unexpected equal inside already started equal")
}

func TestParseSetupPy_DoubleArrayStart(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/double_brackets/setup.py"))
	_, err = lockfile.ParseSetupPy(path)

	assert.ErrorContains(t, err, "unexpected array start inside already started array")
}

func TestParseSetupPy_ArrayEndNoStart(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/array_end_no_start/setup.py"))
	_, err = lockfile.ParseSetupPy(path)

	assert.ErrorContains(t, err, "unexpected array end without start and/or equal")
}

func TestParseSetupPy_BadStringNoEqual(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/bad_string_no_equal/setup.py"))
	_, err = lockfile.ParseSetupPy(path)

	assert.ErrorContains(t, err, "unexpected array start without =")
}

func TestParseSetupPy_BadStringNoArray(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/bad_string_no_array/setup.py"))
	_, err = lockfile.ParseSetupPy(path)

	assert.ErrorContains(t, err, "unexpected string outside of install_requires with equal array")
}

func TestParseSetupPy_UnexpectedText(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/pip/unexpected_text/setup.py"))
	_, err = lockfile.ParseSetupPy(path)

	assert.ErrorContains(t, err, "unexpected text=foo\n)\n")
}
