package models

import "github.com/opencontainers/go-digest"

type ImageOriginDetails struct {
	Index int `json:"index"`
}

type ImageMetadata struct {
	OS            string               `json:"os"`
	LayerMetadata []LayerMetadata      `json:"layer_metadata"`
	BaseImages    [][]BaseImageDetails `json:"base_images"`
}

type BaseImageDetails struct {
	Name string `json:"name"`
	// TODO: Not yet filled in
	Tags []string `json:"tags"`
}

type LayerMetadata struct {
	DiffID         digest.Digest `json:"diff_id"`
	Command        string        `json:"command"`
	IsEmpty        bool          `json:"is_empty"`
	BaseImageIndex int           `json:"base_image_index"`
}
