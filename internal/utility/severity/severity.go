// Package severity provides functionality for calculating vulnerability severity.
package severity

import (
	"errors"
	"strconv"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// Rating represents the severity level of a vulnerability.
type Rating string

const (
	CriticalRating Rating = "CRITICAL"
	HighRating     Rating = "HIGH"
	MediumRating   Rating = "MEDIUM"
	LowRating      Rating = "LOW"
	UnknownRating  Rating = "UNKNOWN"
)

func (r Rating) String() string {
	return string(r)
}

func CalculateScore(severity *osvschema.Severity) (float64, string, error) {
	score := -1.0
	rating := string(UnknownRating)
	var err error
	switch severity.GetType() {
	case osvschema.Severity_UNSPECIFIED:
		// UNSPECIFIED has no score information
	case osvschema.Severity_CVSS_V2:
		var vec *gocvss20.CVSS20
		vec, err = gocvss20.ParseVector(severity.GetScore())
		if err == nil {
			score = vec.BaseScore()
			// CVSS 2.0 does not define a rating, use CVSS 3.0's rating instead
			rating, err = gocvss30.Rating(score)
		}
	case osvschema.Severity_CVSS_V3:
		switch {
		case strings.HasPrefix(severity.GetScore(), "CVSS:3.0"):
			var vec *gocvss30.CVSS30
			vec, err = gocvss30.ParseVector(severity.GetScore())
			if err == nil {
				score = vec.BaseScore()
				rating, err = gocvss30.Rating(score)
			}
		case strings.HasPrefix(severity.GetScore(), "CVSS:3.1"):
			var vec *gocvss31.CVSS31
			vec, err = gocvss31.ParseVector(severity.GetScore())
			if err == nil {
				score = vec.BaseScore()
				rating, err = gocvss31.Rating(score)
			}
		}
	case osvschema.Severity_CVSS_V4:
		var vec *gocvss40.CVSS40
		vec, err = gocvss40.ParseVector(severity.GetScore())
		if err == nil {
			score = vec.Score()
			rating, err = gocvss40.Rating(score)
		}
	case osvschema.Severity_Ubuntu:
		rating = severity.GetScore()
	}

	return score, rating, err
}

func CalculateOverallScore(severities []*osvschema.Severity) (float64, string, error) {
	maxScore := -1.0
	maxRating := string(UnknownRating)

	for _, severity := range severities {
		score, rating, err := CalculateScore(severity)
		if err != nil {
			return -1, string(UnknownRating), err
		}
		if score > maxScore {
			maxScore = score
			maxRating = rating
		}
	}

	return maxScore, maxRating, nil
}

func CalculateScoreBasedOnMostRecentCvssVersionAvailable(severities []*osvschema.Severity) (float64, string, error) {
	mappedSeverities := map[osvschema.Severity_Type]*osvschema.Severity{}
	for _, severity := range severities {
		if _, ok := mappedSeverities[severity.GetType()]; !ok {
			mappedSeverities[severity.GetType()] = severity
		}
	}

	var severity *osvschema.Severity
	for _, severityType := range []osvschema.Severity_Type{osvschema.Severity_CVSS_V4, osvschema.Severity_CVSS_V3, osvschema.Severity_CVSS_V2} {
		if value, ok := mappedSeverities[severityType]; ok {
			severity = value
			break
		}
	}

	if severity == nil {
		return -1, string(UnknownRating), errors.New("no CVSS severity found")
	}

	score, rating, err := CalculateScore(severity)
	if err != nil {
		return -1, string(UnknownRating), err
	}

	return score, rating, nil
}

func CalculateRating(score string) (Rating, error) {
	// All CSVs' rating methods are identical.
	parsedScore, err := strconv.ParseFloat(score, 64)
	if err != nil {
		return UnknownRating, err
	}

	rating, err := gocvss30.Rating(parsedScore)
	if err != nil || rating == "NONE" {
		rating = string(UnknownRating)
	}

	return Rating(rating), err
}
