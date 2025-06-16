package testlogger

import (
	"log/slog"
	"testing"
)

const BeginDirectoryScan = "---Begin Directory Scan---"
const EndDirectoryScan = "---End Directory Scan---"

// BeginDirScanMarker prints out a directory scanning marker during testing to allow snapshots to sort
// the scanning order to allow for unsorted file walks.
func BeginDirScanMarker() {
	if testing.Testing() {
		slog.Info(BeginDirectoryScan)
	}
}

// EndDirScanMarker prints out a directory scanning marker during testing to mark the end of directory walks
func EndDirScanMarker() {
	if testing.Testing() {
		slog.Info(EndDirectoryScan)
	}
}
