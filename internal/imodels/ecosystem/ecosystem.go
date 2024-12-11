package ecosystem

import (
	"encoding/json"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Parsed represents an ecosystem-with-suffix string as defined by the [spec], parsed into
// a structured format.
//
// The suffix is optional and is separated from the ecosystem by a colon.
//
// For example, "Debian:7" would be parsed into Parsed{Ecosystem: constants.EcosystemDebian, Suffix: "7"}
//
// [spec]: https://ossf.github.io/osv-schema/
//
//nolint:recvcheck
type Parsed struct {
	Ecosystem osvschema.Ecosystem
	Suffix    string
}

// UnmarshalJSON handles unmarshalls a JSON string into a Parsed struct.
//
// This method implements the json.Unmarshaler interface.
//
//goland:noinspection GoMixedReceiverTypes
func (p *Parsed) UnmarshalJSON(data []byte) error {
	var str string
	err := json.Unmarshal(data, &str)

	if err != nil {
		return err
	}

	*p = Parse(str)

	return nil
}

// MarshalJSON handles marshals a Parsed struct into a JSON string.
//
// This method implements the json.Marshaler interface.
//
//goland:noinspection GoMixedReceiverTypes
func (p Parsed) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.String() + `"`), nil
}

//goland:noinspection GoMixedReceiverTypes
func (p *Parsed) String() string {
	str := string(p.Ecosystem)

	if p.Suffix != "" {
		str += ":" + p.Suffix
	}

	return str
}

// Parse parses a string into a constants.Ecosystem and an optional suffix specified with a ":"
func Parse(str string) Parsed {
	ecosystem, suffix, _ := strings.Cut(str, ":")

	return Parsed{osvschema.Ecosystem(ecosystem), suffix}
}
