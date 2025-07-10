// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package source

// func TestEnrich(t *testing.T) {
// 	var called bool
// 	var gotAbsModDir, gotGoVersion string

// 	e := &Enricher{
// 		runner: func(ctx context.Context, absModDir string, goVersion string) (map[string][]*Finding, error) {
// 			called = true
// 			gotAbsModDir = absModDir
// 			gotGoVersion = goVersion
// 			return map[string][]*Finding{
// 				"GO-2021-0001": {{OSV: "GO-2021-0001"}},
// 			}, nil
// 		},
// 	}

// 	tmpDir := t.TempDir()
// 	i := &inventory.Inventory{
// 		Packages: []*inventory.Package{
// 			{
// 				Name:      "stdlib",
// 				Version:   "1.20",
// 				Locations: []inventory.Location{{Path: filepath.Join(tmpDir, "go.mod")}},
// 				Plugins:   []string{gomod.Name},
// 			},
// 		},
// 	}

// 	input := &enricher.ScanInput{
// 		ScanRoot: inventory.Path(filepath.Dir(tmpDir)),
// 	}
// 	if err := e.Enrich(context.Background(), input, i); err != nil {
// 		t.Fatalf("Enrich(): %v", err)
// 	}

// 	if !called {
// 		t.Errorf("runner was not called")
// 	}

// 	wantAbsModDir := tmpDir
// 	if gotAbsModDir != wantAbsModDir {
// 		t.Errorf("runner called with absModDir got: %q, want: %q", gotAbsModDir, wantAbsModDir)
// 	}

// 	wantGoVersion := "1.20"
// 	if gotGoVersion != wantGoVersion {
// 		t.Errorf("runner called with goVersion got: %q, want: %q", gotGoVersion, wantGoVersion)
// 	}
// }

// func TestEnrichGoNotInstalled(t *testing.T) {
// 	e := &Enricher{
// 		runner: func(ctx context.Context, absModDir string, goVersion string) (map[string][]*Finding, error) {
// 			t.Error("runner should not be called if go is not installed")
// 			return nil, nil
// 		},
// 	}
// 	// This is a bit of a hack to simulate `go version` failing.
// 	// We can't easily mock exec.Command, so we rely on the fact that a non-existent
// 	// PATH will cause the command to fail.
// 	t.Setenv("PATH", "")

// 	i := &inventory.Inventory{
// 		Packages: []*inventory.Package{
// 			{
// 				Name:      "stdlib",
// 				Version:   "1.20",
// 				Locations: []inventory.Location{{Path: "go.mod"}},
// 				Plugins:   []string{gomod.Name},
// 			},
// 		},
// 	}

// 	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, i); err != nil {
// 		t.Fatalf("Enrich(): %v", err)
// 	}
// }

// func TestEnrichRunnerError(t *testing.T) {
// 	e := &Enricher{
// 		runner: func(ctx context.Context, absModDir string, goVersion string) (map[string][]*Finding, error) {
// 			return nil, fmt.Errorf("runner error")
// 		},
// 	}

// 	tmpDir := t.TempDir()
// 	i := &inventory.Inventory{
// 		Packages: []*inventory.Package{
// 			{
// 				Name:      "stdlib",
// 				Version:   "1.20",
// 				Locations: []inventory.Location{{Path: filepath.Join(tmpDir, "go.mod")}},
// 				Plugins:   []string{gomod.Name},
// 			},
// 		},
// 	}

// 	input := &enricher.ScanInput{
// 		ScanRoot: inventory.Path(filepath.Dir(tmpDir)),
// 	}
// 	if err := e.Enrich(context.Background(), input, i); err != nil {
// 		t.Fatalf("Enrich(): %v", err)
// 	}
// 	// We don't return an error from Enrich, just log it.
// 	// A more advanced test could check the logs.
// }
