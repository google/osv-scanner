package lockfile

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

var errCSVRecordNotEnoughFields = errors.New("not enough fields (expected at least four)")
var errCSVRecordMissingPackageField = errors.New("field 3 is empty (must be the name of a package)")
var errCSVRecordMissingCommitField = errors.New("field 4 is empty (must be a commit)")

func fromCSVRecord(lines []string) (PackageDetails, error) {
	if len(lines) < 4 {
		return PackageDetails{}, errCSVRecordNotEnoughFields
	}

	ecosystem := Ecosystem(lines[0])
	compareAs := Ecosystem(lines[1])
	name := lines[2]
	version := lines[3]
	commit := ""

	if compareAs == "" {
		compareAs = ecosystem
	}

	if ecosystem == "" {
		if version == "" {
			return PackageDetails{}, errCSVRecordMissingCommitField
		}

		commit = version
		version = ""
	}

	if name == "" {
		return PackageDetails{}, errCSVRecordMissingPackageField
	}

	return PackageDetails{
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
		CompareAs: compareAs,
		Commit:    commit,
	}, nil
}

func fromCSV(reader io.Reader) ([]PackageDetails, error) {
	var packages []PackageDetails

	i := 0
	r := csv.NewReader(reader)

	for {
		i++
		record, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return packages, fmt.Errorf("%w", err)
		}

		details, err := fromCSVRecord(record)
		if err != nil {
			return packages, fmt.Errorf("row %d: %w", i, err)
		}

		packages = append(packages, details)
	}

	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}

		return packages[i].Name < packages[j].Name
	})

	return packages, nil
}

func FromCSVRows(filePath string, parseAs string, rows []string) (Lockfile, error) {
	packages, err := fromCSV(strings.NewReader(strings.Join(rows, "\n")))

	return Lockfile{
		FilePath: filePath,
		ParsedAs: parseAs,
		Packages: packages,
	}, err
}

func FromCSVFile(pathToCSV string, parseAs string) (Lockfile, error) {
	reader, err := os.Open(pathToCSV)

	if err != nil {
		return Lockfile{}, fmt.Errorf("could not read %s: %w", pathToCSV, err)
	}

	packages, err := fromCSV(reader)

	if err != nil {
		err = fmt.Errorf("%s: %w", pathToCSV, err)
	}

	return Lockfile{
		FilePath: pathToCSV,
		ParsedAs: parseAs,
		Packages: packages,
	}, err
}
