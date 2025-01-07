package models

type ImageOriginDetails struct {
	DiffID string `json:"diff_id"`

	// TODO: Deprecated, use ImageMetadata to retrieve this info
	OriginCommand string `json:"origin_command"`
	InBaseImage   bool   `json:"in_base_image"`
}

type ImageMetadata struct {
	OS            string          `json:"os"`
	LayerMetadata []LayerMetadata `json:"layer_metadata"`
	// TODO: Not yet filled in
	BaseImages [][]BaseImageDetails `json:"base_images"`
}

type BaseImageDetails struct {
	Name string `json:"name"`
	// TODO: Not yet filled in
	Tags []string `json:"tags"`
}

type LayerMetadata struct {
	DiffID  string `json:"diff_id"`
	Command string `json:"command"`
	IsEmpty bool   `json:"is_empty"`
	// TODO: Not yet filled in
	BaseImageIndex int `json:"base_image_index"`
}
