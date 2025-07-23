// Package ecosystem provides a parser and mappings for ecosystem strings.
package ecosystem

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// ecosystemsWithSuffix documents all the ecosystems that can have a suffix
var ecosystemsWithSuffix = map[osvschema.Ecosystem]struct{}{
	osvschema.EcosystemAlpine:     {},
	osvschema.EcosystemAlmaLinux:  {},
	osvschema.EcosystemAndroid:    {},
	osvschema.EcosystemDebian:     {},
	osvschema.EcosystemMageia:     {},
	osvschema.EcosystemMaven:      {},
	osvschema.EcosystemOpenSUSE:   {},
	osvschema.EcosystemPhotonOS:   {},
	osvschema.EcosystemRedHat:     {},
	osvschema.EcosystemRockyLinux: {},
	osvschema.EcosystemSUSE:       {},
	osvschema.EcosystemUbuntu:     {},
}

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

func (p Parsed) IsEmpty() bool {
	return p.Ecosystem == ""
}

func (p Parsed) Equal(other Parsed) bool {
	// only care about the minor version if both ecosystems have one
	// otherwise we just assume that they're the same and move on
	if p.Suffix != "" && other.Suffix != "" {
		return p.Ecosystem == other.Ecosystem && p.Suffix == other.Suffix
	}

	return p.Ecosystem == other.Ecosystem
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

	*p = MustParse(str)

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

func (p Parsed) String() string {
	str := string(p.Ecosystem)

	if p.Suffix != "" {
		str += ":" + p.Suffix
	}

	return str
}

// MustParse parses a string into a constants.Ecosystem and an optional suffix specified with a ":"
// Panics if there is an invalid ecosystem
func MustParse(str string) Parsed {
	parsed, err := Parse(str)
	if err != nil {
		panic("Failed MustParse: " + err.Error())
	}

	return parsed
}

// Parse parses a string into a constants.Ecosystem and an optional suffix specified with a ":"
func Parse(str string) (Parsed, error) {
	// Special case to return an empty ecosystem if str is empty
	// This is not considered an error.
	if str == "" {
		return Parsed{}, nil
	}

	ecosystem, suffix, _ := strings.Cut(str, ":")

	// Always return the full parsed value even if it might be invalid
	// Let the caller decide how to handle the error
	var err error
	if _, ok := ecosystemsWithSuffix[osvschema.Ecosystem(ecosystem)]; !ok && suffix != "" {
		err = fmt.Errorf("found ecosystem %q has a suffix %q, but it should not", ecosystem, suffix)
	}

	return Parsed{osvschema.Ecosystem(ecosystem), suffix}, err
}
