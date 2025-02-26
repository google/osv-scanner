package main

import (
	"context"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

// muffledHandler eats certain log messages to reduce noise in the test output
type muffledHandler struct {
	slog.TextHandler
}

func (c *muffledHandler) Handle(ctx context.Context, record slog.Record) error {
	// todo: work with the osv-scalibr team to see if we can reduce these
	for _, prefix := range []string{
		"Starting filesystem walk for root:",
		"End status: ",
		"Neither CPE nor PURL found for package",
		"Invalid PURL",
	} {
		if strings.HasPrefix(record.Message, prefix) {
			return nil
		}
	}

	return c.TextHandler.Handle(ctx, record)
}

func newMuffledHandler(w io.Writer) *muffledHandler {
	return &muffledHandler{TextHandler: *slog.NewTextHandler(w, nil)}
}

func Test_FailThis(t *testing.T) {
	t.Fail()
}

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(newMuffledHandler(log.Writer())))

	// ensure a git repository doesn't already exist in the fixtures directory,
	// in case we didn't get a chance to clean-up properly in the last run
	os.RemoveAll("./fixtures/.git")

	// Temporarily make the fixtures folder a git repository to prevent gitignore files messing with tests.
	_, err := git.PlainInit("./fixtures", false)
	if err != nil {
		panic(err)
	}
	code := m.Run()

	testutility.CleanSnapshots(m)

	os.RemoveAll("./fixtures/.git")
	os.Exit(code)
}
