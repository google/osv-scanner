package testcmd

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
)

func determineRecorderMode() recorder.Mode {
	switch strings.ToLower(os.Getenv("TEST_VCR_MODE")) {
	case "recordonly", "0":
		return recorder.ModeRecordOnly
	case "replayonly", "1":
		return recorder.ModeReplayOnly
	case "replaywithnewepisodes", "2":
		return recorder.ModeReplayWithNewEpisodes
	case "recordonce", "3":
		return recorder.ModeRecordOnce
	case "passthrough", "4":
		return recorder.ModePassthrough
	}

	if _, inCI := os.LookupEnv("CI"); inCI {
		return recorder.ModeReplayOnly
	}

	return recorder.ModeRecordOnce
}

// InsertCassette returns an http.Client backed by a [recorder.Recorder] which
// will record and (re)play responses from a cassette based on the tests name
func InsertCassette(t *testing.T) *http.Client {
	t.Helper()

	r, err := recorder.New(
		filepath.Join("testdata/cassettes", strings.ReplaceAll(t.Name(), "/", "_")),
		recorder.WithSkipRequestLatency(true),
		recorder.WithMode(determineRecorderMode()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Stop(); err != nil {
			t.Error(err)
		}
	})

	return r.GetDefaultClient()
}
