package testcmd

import "bytes"

// muffledHandler eats certain log messages to reduce noise in the test output
type muffledWriter struct {
	*bytes.Buffer
}

func (m muffledWriter) Write(p []byte) (int, error) {
	// todo: work with the osv-scalibr team to see if we can reduce these
	for _, prefix := range []string{
		"Starting filesystem walk for root:",
		"End status: ",
		"Neither CPE nor PURL found for package",
		"Invalid PURL",
		"os-release[ID] not set, fallback to",
		"VERSION_ID not set in os-release",
		"osrelease.ParseOsRelease(): file does not exist",
	} {
		if bytes.HasPrefix(p, []byte(prefix)) {
			return len(p), nil
		}
	}

	return m.Buffer.Write(p)
}

func newMuffledWriter() muffledWriter {
	return muffledWriter{Buffer: &bytes.Buffer{}}
}
