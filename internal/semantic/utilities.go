package semantic

import (
	"fmt"
	"math/big"
)

func convertToBigIntOrPanic(str string) *big.Int {
	if num, isNumber := convertToBigInt(str); isNumber {
		return num
	}

	panic(fmt.Sprintf("failed to convert %s to a number", str))
}

func convertToBigInt(str string) (*big.Int, bool) {
	i, ok := new(big.Int).SetString(str, 10)

	return i, ok
}

func minInt(x, y int) int {
	if x > y {
		return y
	}

	return x
}

func maxInt(x, y int) int {
	if x < y {
		return y
	}

	return x
}

func fetch(slice []string, i int, def string) string {
	if len(slice) <= i {
		return def
	}

	return slice[i]
}
