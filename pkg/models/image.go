package models

type ImageOriginDetails struct {
	LayerID       string `json:"layerID"`
	OriginCommand string `json:"originCommand"`
	InBaseImage   bool   `json:"inBaseImage"`
}
