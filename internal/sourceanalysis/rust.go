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
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"github.com/google/osv-scanner/internal/thirdparty/ar"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/ianlancetaylor/demangle"
)

const (
	// - opt-level=3 (Use the highest optimisation level (default with --release))
	// - debuginfo=1 (Include DWARF debug info which is extracted to find which funcs are called)
	// - embed-bitcode=yes (Required to enable LTO)
	// - lto (Enable full link time optimisation, this allows unused dynamic dispatch calls to be optimised out)
	// - codegen-units=1 (Build everything in one codegen unit, increases build time but enables more optimisations
	//                  and make libraries only generate one object file)
	RustFlagsEnv     = "RUSTFLAGS=-C opt-level=3 -C debuginfo=1 -C embed-bitcode=yes -C lto -C codegen-units=1 -C strip=none"
	RustLibExtension = ".rcgu.o/"
)

func rustAnalysis(r reporter.Reporter, pkgs []models.PackageVulns, source models.SourceInfo) {
	binaryPaths, err := rustBuildSource(r, source)
	if err != nil {
		r.Errorf("failed to build cargo/rust project from source: %s\n", err)
		return
	}

	// This map stores 3 states for each vuln ID
	// - There is function level vuln info, but it **wasn't** called   (false)
	// - There is function level vuln info, and it **is** called    (true)
	// - There is **no** functional level vuln info, so we don't know whether it is called (doesn't exist)
	isCalledVulnMap := map[string]bool{}

	for _, path := range binaryPaths {
		var readAt io.ReaderAt
		if strings.HasSuffix(path, ".rlib") {
			// Is a library, so need an extra step to extract the object binary file before passing to parseDWARFData
			buf, err := extractRlibArchive(path)
			if err != nil {
				r.Errorf("failed to analyse '%s': %s\n", path, err)
				continue
			}
			readAt = bytes.NewReader(buf.Bytes())
		} else {
			f, err := os.Open(path)
			if err != nil {
				r.Errorf("failed to read binary '%s': %s\n", path, err)
				continue
			}
			// This is fine to defer til the end of the function as there's
			// generally single digit number of binaries in a project
			defer f.Close()
			readAt = f
		}

		calls, err := functionsFromDWARF(readAt)
		if err != nil {
			r.Errorf("failed to analyse '%s': %s\n", path, err)
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
							isCalledVulnMap[v.ID] = isCalledVulnMap[v.ID] || called
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

					called, hasFuncInfo := isCalledVulnMap[vulnID]
					if hasFuncInfo {
						(*analysis)[vulnID] = models.AnalysisInfo{
							Called: called,
						}
					}
				}
			}
		}
	}
}

func functionsFromDWARF(readAt io.ReaderAt) (map[string]struct{}, error) {
	output := map[string]struct{}{}
	file, err := elf.NewFile(readAt)
	if err != nil {
		return nil, fmt.Errorf("failed to read binary: %w", err)
	}
	dwarfData, err := file.DWARF()
	if err != nil {
		return nil, fmt.Errorf("failed to extract debug symbols from binary: %w", err)
	}
	entryReader := dwarfData.Reader()

	for {
		entry, err := entryReader.Next()
		if errors.Is(err, io.EOF) || entry == nil {
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

			val = cleanRustFunctionSymbols(val)
			output[val] = struct{}{}
		}
	}

	return output, nil
}

// extractRlibArchive return the file path to a temporary ELF Object file extracted from the given rlib.
//
// It is the callers responsibility to remove the temporary file
func extractRlibArchive(rlibPath string) (bytes.Buffer, error) {
	buf := bytes.Buffer{}
	rlibFile, err := os.Open(rlibPath)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to open .rlib file '%s': %w", rlibPath, err)
	}

	reader, err := ar.NewReader(rlibFile)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf(".rlib file '%s' is not valid ar archive: %w", rlibPath, err)
	}
	for {
		header, err := reader.Next()
		if err != nil {
			log.Fatalf("%v", err)
		}
		if header.Name == "//" { // "//" is used in GNU ar format as a store for long file names
			fileBuf := bytes.Buffer{}
			// Ignore the error here as it's likely
			_, err = io.Copy(&fileBuf, reader)
			if err != nil {
				return bytes.Buffer{}, fmt.Errorf("failed to read // store in ar archive: %w", err)
			}

			filename := strings.TrimSpace(fileBuf.String())

			// There should only be one file (since we set codegen-units=1)
			if !strings.HasSuffix(filename, RustLibExtension) {
				// TODO: Verify this, and return an error here instead.
				log.Printf("rlib archive contents were unexpected: %s\n", filename)
			}
		}
		// /0 indicates the first file mentioned in the "//" store
		if header.Name == "/0" || strings.HasSuffix(header.Name, RustLibExtension) {
			break
		}
	}
	_, err = io.Copy(&buf, reader)
	if err != nil {
		return bytes.Buffer{}, fmt.Errorf("failed to read from archive '%s': %w", rlibPath, err)
	}

	return buf, nil
}

func rustBuildSource(r reporter.Reporter, source models.SourceInfo) ([]string, error) {
	projectBaseDir := filepath.Dir(source.Path)

	cmd := exec.Command("cargo", "build", "--workspace", "--all-targets", "--release")
	cmd.Env = append(cmd.Environ(), RustFlagsEnv)
	cmd.Dir = projectBaseDir
	if errors.Is(cmd.Err, exec.ErrDot) {
		cmd.Err = nil
	}

	stdoutBuffer := bytes.Buffer{}
	stderrBuffer := bytes.Buffer{}
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer

	r.Infof("Begin building rust/cargo project\n")

	if err := cmd.Run(); err != nil {
		r.Errorf("cargo stdout:\n%s", stdoutBuffer.String())
		r.Errorf("cargo stderr:\n%s", stderrBuffer.String())

		return nil, fmt.Errorf("failed to run `%v`: %w", cmd.String(), err)
	}

	outputDir := filepath.Join(projectBaseDir, "target", "release")
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read \"%s\" dir: %w", outputDir, err)
	}

	resultBinaryPaths := []string{}
	for _, de := range entries {
		// We only want .d files, which is generated for each output binary from cargo
		// These files contains a string to the full path of output binary/library file.
		// This is a reasonably reliable way to identify the output in a cross platform way.
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
			return nil, errors.New("file path contains ': ', which is unsupported")
		}
		resultBinaryPaths = append(resultBinaryPaths, fileSplit[0])
	}

	return resultBinaryPaths, nil
}

// cleanRustFunctionSymbols takes in demanged rust symbols and makes them fit format of
// the common function level advisory information
func cleanRustFunctionSymbols(val string) string {
	// Used to remove generics from functions and types as they are not included in function calls
	// in advisories:
	// E.g.: `smallvec::SmallVec<A>::new` => `smallvec::SmallVec::new`
	//
	// Usage: antiGenericRegex.ReplaceAllString(val, "")
	var antiGenericRegex = cachedregexp.MustCompile(`<[\w,]+>`)
	val = antiGenericRegex.ReplaceAllString(val, "")

	// Used to remove fully qualified trait implementation indicators from the function type,
	// since those are generally not included in advisory:
	// E.g.: `<libflate::gzip::MultiDecoder as std::io::Read>::read` => `libflate::gzip::MultiDecoder::read`
	var antiTraitImplRegex = cachedregexp.MustCompile(`<(.*) as .*>`)
	val = antiTraitImplRegex.ReplaceAllString(val, "$1")

	return val
}
