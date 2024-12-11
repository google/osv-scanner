package lockfile_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"
)

type devGroupTestCase struct {
	name       string
	scopes     []string
	isDevGroup bool
}

func TestIsDevGroup_Maven(t *testing.T) {
	t.Parallel()
	testCases := []devGroupTestCase{
		{name: "compile", scopes: []string{"compile"}, isDevGroup: false},
		{name: "provided", scopes: []string{"provided"}, isDevGroup: false},
		{name: "runtime", scopes: []string{"runtime"}, isDevGroup: false},
		{name: "test", scopes: []string{"test"}, isDevGroup: true},
		{name: "system", scopes: []string{"system"}, isDevGroup: false},
	}

	runTestCases(t, lockfile.MavenEcosystem, testCases)
}

func TestIsDevGroup_Gradle(t *testing.T) {
	t.Parallel()
	testCases := []devGroupTestCase{
		{name: "annotation", scopes: []string{"annotationProcessor"}, isDevGroup: false},
		{name: "api", scopes: []string{"compileClasspath", "testRuntimeClasspath", "annotationProcessor"}, isDevGroup: false},
		{name: "compileOnly", scopes: []string{"compileClasspath"}, isDevGroup: false},
		{name: "compileOnlyApi", scopes: []string{"compileClasspath", "testCompileClasspath"}, isDevGroup: false},
		{name: "implementation", scopes: []string{"compileClasspath", "testCompileClasspath", "testRuntimeClasspath"}, isDevGroup: false},
		// We create a fake scope when matching locations whenever we see a runtimeOnly instruction as it does not appear in the lockfile
		{name: "runtimeOnly", scopes: []string{"testRuntimeClasspath", "runtimeClasspath"}, isDevGroup: false},
		{name: "testCompileOnly", scopes: []string{"testCompileClasspath"}, isDevGroup: true},
		{name: "testImplementation", scopes: []string{"testCompileClasspath", "testRuntimeClasspath"}, isDevGroup: true},
		{name: "testRuntimeOnly", scopes: []string{"testRuntimeClasspath"}, isDevGroup: true},
	}

	runTestCases(t, lockfile.MavenEcosystem, testCases)
}

func runTestCases(t *testing.T, ecosystem lockfile.Ecosystem, testCases []devGroupTestCase) {
	t.Helper()
	for _, testCase := range testCases {
		tt := testCase
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ecosystem.IsDevGroup(tt.scopes)
			assert.Equal(t, tt.isDevGroup, result)
		})
	}
}
