package semantic

import (
	"math/big"
	"strings"
)

type CRANVersion struct {
	components Components
}

func (v CRANVersion) Compare(w CRANVersion) int {
	if diff := v.components.Cmp(w.components); diff != 0 {
		return diff
	}

	if len(v.components) == len(w.components) {
		return 0
	}

	if len(v.components) > len(w.components) {
		return 1
	}

	return -1
}

func (v CRANVersion) CompareStr(str string) int {
	return v.Compare(parseCRANVersion(str))
}

func parseCRANVersion(str string) CRANVersion {
	str = strings.ReplaceAll(str, "-", ".")

	splitted := strings.Split(str, ".")

	components := make(Components, 0, len(splitted))

	for _, s := range splitted {
		v, _ := new(big.Int).SetString(s, 10)

		components = append(components, v)
	}

	return CRANVersion{components}
}
