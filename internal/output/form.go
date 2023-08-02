package output

// Form returns the singular or plural form that should be used based on the given count
func Form(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}

	return plural
}
