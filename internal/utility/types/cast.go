// Package types provides type conversion utility functions
package types

func MustCastSlice[OUT, IN any](a []IN) []OUT {
	out := make([]OUT, len(a))
	for i := range a {
		out[i] = any(a[i]).(OUT)
	}

	return out
}
