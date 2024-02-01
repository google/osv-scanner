package severity

import (
	"strings"

	"github.com/google/osv-scanner/pkg/models"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

func CalculateScore(severity models.Severity) (float64, string, error) {
	score := -1.0
	rating := "UNKNOWN"
	var err error
	switch severity.Type {
	case models.SeverityCVSSV2:
		var vec *gocvss20.CVSS20
		vec, err = gocvss20.ParseVector(severity.Score)
		if err == nil {
			score = vec.BaseScore()
			// CVSS 2.0 does not define a rating, use CVSS 3.0's rating instead
			rating, err = gocvss30.Rating(score)
		}
	case models.SeverityCVSSV3:
		switch {
		case strings.HasPrefix(severity.Score, "CVSS:3.0"):
			var vec *gocvss30.CVSS30
			vec, err = gocvss30.ParseVector(severity.Score)
			if err == nil {
				score = vec.BaseScore()
				rating, err = gocvss30.Rating(score)
			}
		case strings.HasPrefix(severity.Score, "CVSS:3.1"):
			var vec *gocvss31.CVSS31
			vec, err = gocvss31.ParseVector(severity.Score)
			if err == nil {
				score = vec.BaseScore()
				rating, err = gocvss31.Rating(score)
			}
		}
	case models.SeverityCVSSV4:
		var vec *gocvss40.CVSS40
		vec, err = gocvss40.ParseVector(severity.Score)
		if err == nil {
			score = vec.Score()
			rating, err = gocvss40.Rating(score)
		}
	}

	return score, rating, err
}
