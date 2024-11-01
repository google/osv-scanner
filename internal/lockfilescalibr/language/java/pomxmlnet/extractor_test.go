package pomxmlnet_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scanner/internal/lockfilescalibr/language/java/pomxmlnet"
	"github.com/google/osv-scanner/internal/resolution/clienttest"
	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/testutility"
)

func TestMavenResolverExtractor_FileRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{
			path: "",
			want: false,
		},
		{
			path: "pom.xml",
			want: true,
		},
		{
			path: "path/to/my/pom.xml",
			want: true,
		},
		{
			path: "path/to/my/pom.xml/file",
			want: false,
		},
		{
			path: "path/to/my/pom.xml.file",
			want: false,
		},
		{
			path: "path.to.my.pom.xml",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			e := pomxmlnet.Extractor{}
			got := e.FileRequired(tt.path, nil)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	t.Parallel()

	tests := []extracttest.TestTableEntry{
		{
			Name: "Not a pom file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/maven/not-pom.txt",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "invalid xml syntax",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/maven/invalid-syntax.xml",
			},
			WantErr: extracttest.ContainsErrStr{Str: "XML syntax error"},
		},
		{
			Name: "empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/maven/empty.xml",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/maven/one-package.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.apache.maven:maven-artifact",
					Version:   "1.0.0",
					Locations: []string{"testdata/maven/one-package.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/maven/two-packages.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "io.netty:netty-all",
					Version:   "4.1.42.Final",
					Locations: []string{"testdata/maven/two-packages.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:      "org.slf4j:slf4j-log4j12",
					Version:   "1.7.25",
					Locations: []string{"testdata/maven/two-packages.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
			},
		},
		{
			Name: "with dependency management",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/maven/with-dependency-management.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "io.netty:netty-all",
					Version:   "4.1.9",
					Locations: []string{"testdata/maven/with-dependency-management.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:      "org.slf4j:slf4j-log4j12",
					Version:   "1.7.25",
					Locations: []string{"testdata/maven/with-dependency-management.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
			},
		},
		{
			Name: "interpolation",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/maven/interpolation.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.mine:mypackage",
					Version:   "1.0.0",
					Locations: []string{"testdata/maven/interpolation.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:      "org.mine:my.package",
					Version:   "2.3.4",
					Locations: []string{"testdata/maven/interpolation.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:      "org.mine:ranged-package",
					Version:   "9.4.37",
					Locations: []string{"testdata/maven/interpolation.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
			},
		},
		{
			Name: "with scope / dep groups",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/maven/with-scope.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "junit:junit",
					Version:   "4.12",
					Locations: []string{"testdata/maven/with-scope.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{"runtime"}},
				},
			},
		},
		{
			Name: "transitive dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/maven/transitive.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.direct:alice",
					Version:   "1.0.0",
					Locations: []string{"testdata/maven/transitive.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:      "org.direct:bob",
					Version:   "2.0.0",
					Locations: []string{"testdata/maven/transitive.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:      "org.direct:chris",
					Version:   "3.0.0",
					Locations: []string{"testdata/maven/transitive.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:      "org.transitive:chuck",
					Version:   "1.1.1",
					Locations: []string{"testdata/maven/transitive.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:      "org.transitive:dave",
					Version:   "2.2.2",
					Locations: []string{"testdata/maven/transitive.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:      "org.transitive:eve",
					Version:   "3.3.3",
					Locations: []string{"testdata/maven/transitive.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:      "org.transitive:frank",
					Version:   "4.4.4",
					Locations: []string{"testdata/maven/transitive.xml"},
					Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			resolutionClient := clienttest.NewMockResolutionClient(t, "testdata/universe/basic-universe.yaml")
			extr := pomxmlnet.Extractor{
				DependencyClient:       resolutionClient,
				MavenRegistryAPIClient: &datasource.MavenRegistryAPIClient{},
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantInventory, got, cmpopts.SortSlices(extracttest.InventoryCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}

func TestExtractor_Extract_WithMockServer(t *testing.T) {
	t.Parallel()

	tt := extracttest.TestTableEntry{
		// Name: "with parent",
		InputConfig: extracttest.ScanInputMockConfig{
			Path: "testdata/maven/with-parent.xml",
		},
		WantInventory: []*extractor.Inventory{
			{
				Name:      "org.alice:alice",
				Version:   "1.0.0",
				Locations: []string{"testdata/maven/with-parent.xml"},
				Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
			},
			{
				Name:      "org.bob:bob",
				Version:   "2.0.0",
				Locations: []string{"testdata/maven/with-parent.xml"},
				Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
			},
			{
				Name:      "org.chuck:chuck",
				Version:   "3.0.0",
				Locations: []string{"testdata/maven/with-parent.xml"},
				Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
			},
			{
				Name:      "org.dave:dave",
				Version:   "4.0.0",
				Locations: []string{"testdata/maven/with-parent.xml"},
				Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
			},
			{
				Name:      "org.eve:eve",
				Version:   "5.0.0",
				Locations: []string{"testdata/maven/with-parent.xml"},
				Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
			},
			{
				Name:      "org.frank:frank",
				Version:   "6.0.0",
				Locations: []string{"testdata/maven/with-parent.xml"},
				Metadata:  osv.DepGroupMetadata{DepGroupVals: []string{}},
			},
		},
	}

	srv := testutility.NewMockHTTPServer(t)
	srv.SetResponse(t, "org/upstream/parent-pom/1.0/parent-pom-1.0.pom", []byte(`
	<project>
	  <groupId>org.upstream</groupId>
	  <artifactId>parent-pom</artifactId>
	  <version>1.0</version>
	  <packaging>pom</packaging>
		<dependencies>
      <dependency>
        <groupId>org.eve</groupId>
        <artifactId>eve</artifactId>
        <version>5.0.0</version>
      </dependency>
		</dependencies>
	</project>
	`))
	srv.SetResponse(t, "org/import/import/1.2.3/import-1.2.3.pom", []byte(`
	<project>
	  <groupId>org.import</groupId>
	  <artifactId>import</artifactId>
	  <version>1.2.3</version>
	  <packaging>pom</packaging>
	  <dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>org.frank</groupId>
          <artifactId>frank</artifactId>
          <version>6.0.0</version>
        </dependency>
      </dependencies>
	  </dependencyManagement>
	</project>
	`))

	apiClient, err := datasource.NewMavenRegistryAPIClient(srv.URL)
	if err != nil {
		t.Fatalf("%v", err)
	}

	resolutionClient := clienttest.NewMockResolutionClient(t, "testdata/universe/basic-universe.yaml")
	extr := pomxmlnet.Extractor{
		DependencyClient:       resolutionClient,
		MavenRegistryAPIClient: apiClient,
	}

	scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
	defer extracttest.CloseTestScanInput(t, scanInput)

	got, err := extr.Extract(context.Background(), &scanInput)

	if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
		t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
		return
	}

	if diff := cmp.Diff(tt.WantInventory, got, cmpopts.SortSlices(extracttest.InventoryCmpLess)); diff != "" {
		t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
	}
}
