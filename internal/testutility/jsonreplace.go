package testutility

import (
	"github.com/tidwall/gjson"
)

type JSONReplaceRule struct {
	Path        string
	ReplaceFunc func(toReplace gjson.Result) any
}

var (
	OnlyIDVulnsRule = JSONReplaceRule{
		Path: "results.#.packages.#.vulnerabilities",
		ReplaceFunc: func(toReplace gjson.Result) any {
			return toReplace.Get("#.id").Value()
		},
	}
	GroupsAsArrayLen = JSONReplaceRule{
		Path: "results.#.packages.#.groups",
		ReplaceFunc: func(toReplace gjson.Result) any {
			if toReplace.IsArray() {
				return len(toReplace.Array())
			}

			return 0
		},
	}
	OnlyFirstBaseImage = JSONReplaceRule{
		Path: "image_metadata.base_images.#",
		ReplaceFunc: func(toReplace gjson.Result) any {
			if toReplace.IsArray() && len(toReplace.Array()) >= 1 {
				return toReplace.Array()[0].Value()
			}

			return struct{}{}
		},
	}
	ShortenHistoryCommandLength = JSONReplaceRule{
		Path: "image_metadata.layer_metadata.#.command",
		ReplaceFunc: func(toReplace gjson.Result) any {
			if len(toReplace.String()) > 28 {
				return toReplace.String()[:25] + "..."
			}

			return toReplace.String()
		},
	}
)
