// Copied from
// https://github.com/golang/vuln/blob/267a472bf377fa105988693c2a597d2b8de36ad8/internal/govulncheck/handler.go
// and modified.

package govulncheck

import (
	"encoding/json"
	"io"
)

// Handler handles messages to be presented in a vulnerability scan output
// stream.
type Handler interface {
	// Finding is called for each vulnerability finding in the stream.
	Finding(finding *Finding) error
}

// HandleJSON reads the json from the supplied stream and hands the decoded
// output to the handler.
func HandleJSON(from io.Reader, to Handler) error {
	dec := json.NewDecoder(from)
	for dec.More() {
		msg := Message{}
		// decode the next message in the stream
		if err := dec.Decode(&msg); err != nil {
			return err
		}
		// dispatch the message
		var err error
		if msg.Finding != nil {
			err = to.Finding(msg.Finding)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
