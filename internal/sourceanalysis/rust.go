package sourceanalysis

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scanner/internal/sourceanalysis/ar"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/ianlancetaylor/demangle"
)

const RUST_FLAGS_ENV = "RUSTFLAGS=-C opt-level=3 -C debuginfo=1"
const RUST_LIB_EXTENSION = ".rcgu.o/"

// Used to remove generics from functions and types as they are not included in function calls
// in advisories:
// E.g.: `smallvec::SmallVec<A>::new` => `smallvec::SmallVec::new`
var antiGenericRegex = regexp.MustCompile(`<[\w,]+>`)

// Used to remove fully qualified trait implementation indicators from the function type,
// since those are generally not included in advisorie:
// E.g.: `<libflate::gzip::MultiDecoder as std::io::Read>::read` => `libflate::gzip::MultiDecoder::read`
var antiTraitImplRegex = regexp.MustCompile(`<(.*) as .*>`)

func rustAnalysis(r reporter.Reporter, pkgs []models.PackageVulns, source models.SourceInfo) {
	binaryPaths, err := rustBuildSource(r, source)
	if err != nil {
		r.PrintError(fmt.Sprintf("failed to build cargo/rust project from source: %s", err))
		return
	}

	isCalledMap := map[string]bool{}

	for _, path := range binaryPaths {
		if strings.HasSuffix(path, ".rlib") {
			// Is a library, so need an extra step to extract the object binary file before passing to parseDWARFData
			objFile, err := extractRlibArchive(path)
			if err != nil {
				r.PrintError(fmt.Sprintf("failed to analyse '%s': %s", path, err))
				continue
			}
			path = objFile.Name()
			objFile.Close()
			// TODO: Do we need to care about error on deletion here?
			defer os.Remove(path)
		}
		calls, err := parseDWARFData(r, path)
		if err != nil {
			r.PrintError(fmt.Sprintf("failed to analyse '%s': %s", path, err))
			continue
		}

		for _, pv := range pkgs {
			for _, v := range pv.Vulnerabilities {
				for _, a := range v.Affected {
					// Example of RUSTSEC function level information:
					//
					// "affects": {
					//     "os": [],
					//     "functions": [
					//         "smallvec::SmallVec::grow"
					//     ],
					//     "arch": []
					// }
					ecosystemAffects, ok := a.EcosystemSpecific["affects"].(map[string]interface{})
					if !ok {
						continue
					}
					affectedFunctions, ok := ecosystemAffects["functions"].([]interface{})
					if !ok {
						continue
					}
					for _, f := range affectedFunctions {
						if funcName, ok := f.(string); ok {
							_, called := calls[funcName]
							// Once one advisory marks this vuln as called, always mark as called
							isCalledMap[v.ID] = isCalledMap[v.ID] || called
						}
					}
				}
			}
		}

		for _, pv := range pkgs {
			for groupIdx := range pv.Groups {
				for _, vulnID := range pv.Groups[groupIdx].IDs {
					analysis := &pv.Groups[groupIdx].ExperimentalAnalysis
					if *analysis == nil {
						*analysis = make(map[string]models.AnalysisInfo)
					}

					called, checked := isCalledMap[vulnID]
					if checked {
						(*analysis)[vulnID] = models.AnalysisInfo{
							Called: called, // If call hasn't been checked, assume it's been called
						}
					}
				}
			}
		}
	}
}

func parseDWARFData(r reporter.Reporter, binaryPath string) (map[string]struct{}, error) {
	output := map[string]struct{}{}
	file, err := elf.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open binary %s: %w", binaryPath, err)
	}
	dwarfData, err := file.DWARF()
	if err != nil {
		return nil, fmt.Errorf("failed to extract debug symbols from binary %s: %w", binaryPath, err)
	}
	entryReader := dwarfData.Reader()

	for {
		entry, err := entryReader.Next()
		if err == io.EOF || entry == nil {
			// We've reached the end of DWARF entries
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error parsing binary DWARF data: %w", err)
		}

		// We only care about contents in functions
		if entry.Tag != dwarf.TagSubprogram {
			continue
		}
		// Go through fields
		for _, field := range entry.Field {
			// We only care about linkage names (including function names)
			if field.Attr != dwarf.AttrLinkageName {
				continue
			}

			val, err := demangle.ToString(field.Val.(string), demangle.NoClones)
			if err != nil {
				// most likely not a rust function, so just ignore it
				continue
			}
			val = antiGenericRegex.ReplaceAllString(val, "")
			output[val] = struct{}{}
		}
	}

	return output, nil
}

// extractRlibArchive return the file handle to a temporary ELF Object file extracted from the given rlib.
//
// It is the callers responsibility to remove the temporary file
func extractRlibArchive(rlibPath string) (*os.File, error) {
	file, err := os.CreateTemp("", "rust-*.o")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	rlibFile, err := os.Open(rlibPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open .rlib file '%s': %w", rlibPath, err)
	}

	reader, err := ar.NewReader(rlibFile)
	if err != nil {
		return nil, fmt.Errorf(".rlib file '%s' is not valid ar archive: %w", rlibPath, err)
	}
	for {
		header, err := reader.Next()
		if err != nil {
			log.Fatalf("%v", err)
		}
		if header.Name == "//" { // "//" is used in GNU ar format as a store for long file names
			fileBuf := bytes.Buffer{}
			io.Copy(&fileBuf, reader)
			// There should only be one file (since we set codegen-units=1)
			if !strings.HasSuffix(fileBuf.String(), RUST_LIB_EXTENSION) {
				// TODO: Verify this, and return an error here instead.
				log.Printf("rlib archive contents were unexpected: %s\n", fileBuf.String())
			}
		}
		// /0 indicates the first file mentioned in the "//" store
		if header.Name == "/0" || strings.HasSuffix(header.Name, RUST_LIB_EXTENSION) {
			break
		}
	}
	io.Copy(file, reader)
	err = file.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to write to temporary file '%s': %w", file.Name(), err)
	}

	return file, nil
}

func rustBuildSource(r reporter.Reporter, source models.SourceInfo) ([]string, error) {
	projectBaseDir := filepath.Dir(source.Path)

	cmd := exec.Command("cargo", "build", "--all-targets", "--release")
	cmd.Env = append(cmd.Environ(), RUST_FLAGS_ENV)
	cmd.Dir = projectBaseDir
	if errors.Is(cmd.Err, exec.ErrDot) {
		cmd.Err = nil
	}

	stdoutBuffer := bytes.Buffer{}
	stderrBuffer := bytes.Buffer{}
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer

	r.PrintText("Begin building rust/cargo project\n")

	if err := cmd.Run(); err != nil {
		r.PrintError(fmt.Sprintf("cargo stdout:\n%s", stdoutBuffer.String()))
		r.PrintError(fmt.Sprintf("cargo stderr:\n%s", stderrBuffer.String()))

		return nil, fmt.Errorf("failed to run cargo build: %w", err)
	}

	outputDir := filepath.Join(projectBaseDir, "target", "debug")
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read \"%s\" dir: %w", outputDir, err)
	}

	resultBinaryPaths := []string{}
	for _, de := range entries {
		// We only want .d files
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".d") {
			continue
		}

		file, err := os.ReadFile(filepath.Join(outputDir, de.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to read \"%s\": %w", filepath.Join(outputDir, de.Name()), err)
		}

		fileSplit := strings.Split(string(file), ": ")
		if len(fileSplit) != 2 {
			// TODO: this can probably be fixed with more effort
			return nil, fmt.Errorf("file path contains ': ', which is unsupported")
		}
		resultBinaryPaths = append(resultBinaryPaths, fileSplit[0])
	}

	return resultBinaryPaths, nil
}
