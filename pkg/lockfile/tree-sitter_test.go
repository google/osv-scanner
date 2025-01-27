package lockfile_test

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_ParseFile(t *testing.T) {
	t.Parallel()

	sourcefile, err := lockfile.OpenLocalDepFile("fixtures/bundler/groups/Gemfile")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	res, err := lockfile.ParseFile(sourcefile, lockfile.Ruby)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	defer res.Close()

	gemsCount := 0
	err = res.Node.Query(`(
		(call
			method: (identifier) @method_name
			(#match? @method_name "gem")
			arguments: (argument_list
				.
				[
				  (string)
					(pair)
				  ","
				]* @gem_call_argument
			)
		) @gem_call
	)`, func(match *lockfile.MatchResult) error {
		gemsCount++

		methodNameNode := match.FindFirstByName("method_name")
		methodName, err := match.Ctx.ExtractTextValue(methodNameNode.TSNode)
		if err != nil {
			return err
		}
		assert.Equal(t, "gem", methodName)

		argumentNodes := match.FindByName("gem_call_argument")
		depNameNode := argumentNodes[0]
		depName, err := match.Ctx.ExtractTextValue(depNameNode.TSNode)
		if err != nil {
			return err
		}

		if depName == "timeout" {
			assert.Len(t, argumentNodes, 7)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	assert.Equal(t, 6, gemsCount)
}

func Test_ParseFile_BadQuery(t *testing.T) {
	t.Parallel()

	sourcefile, err := lockfile.OpenLocalDepFile("fixtures/bundler/one-package/Gemfile")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	res, err := lockfile.ParseFile(sourcefile, lockfile.Ruby)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	defer res.Close()

	err = res.Node.Query(`((call)`, func(match *lockfile.MatchResult) error {
		t.Fatalf("Got unexpected match")
		return nil
	})

	assert.ErrorContains(t, err, "Invalid syntax")
}

func Test_ParseFile_Error(t *testing.T) {
	t.Parallel()

	sourcefile, err := lockfile.OpenLocalDepFile("fixtures/bundler/groups/Gemfile.lock")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	_, err = lockfile.ParseFile(sourcefile, lockfile.Ruby)

	assert.ErrorContains(t, err, "Error parsing")
}
