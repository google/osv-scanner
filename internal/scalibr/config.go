package scalibr

import (
	"io"
	"net/http"

	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
)

func NewPluginConfig(httpClient *http.Client, userAgent string) (*scalibrconfig.PluginConfig, io.Closer) {
	cf := NewClientFactories(httpClient, userAgent)

	return &scalibrconfig.PluginConfig{ClientFactories: cf}, cf
}
