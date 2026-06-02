package gitlab

// CVSSRating contains a CVSS vector and the vendor that assigned the rating.
type CVSSRating struct {
	Vendor string `json:"vendor"`
	Vector string `json:"vector"`
}
