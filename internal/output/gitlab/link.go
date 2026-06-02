package gitlab

// Link contains the hyperlink to the detailed information about a vulnerability.
type Link struct {
	URL string `json:"url"` // URL of the document (mandatory)
}
