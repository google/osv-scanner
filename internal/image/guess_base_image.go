package image

import (
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Originally from https://github.com/aquasecurity/trivy/blob/1f5f34895823fae81bf521fc939bee743a50e304/pkg/fanal/image/image.go#L111
// Modified to return non empty index

// GuessBaseImageIndex tries to guess index of base layer. Index counting only non empty layers.
//
// e.g. In the following example, we should detect layers in debian:8.
//
//	FROM debian:8
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"]
//	CMD ["somecmd"]
//
// debian:8 may be like
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]
//
// In total, it would be like:
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]              # empty layer (detected)
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"] # empty layer (skipped)
//	CMD ["somecmd"]              # empty layer (skipped)
//
// This method tries to detect CMD in the second line and assume the first line is a base layer.
//  1. Iterate histories from the bottom.
//  2. Skip all the empty layers at the bottom. In the above example, "entrypoint.sh" and "somecmd" will be skipped
//  3. If it finds CMD, it assumes that it is the end of base layers.
//  4. It gets all the layers as base layers above the CMD found in #3.
func guessBaseImageIndex(histories []v1.History) int {
	baseImageIndex := -1
	var foundNonEmpty bool
	for i := len(histories) - 1; i >= 0; i-- {
		h := histories[i]

		// Skip the last CMD, ENTRYPOINT, etc.
		if !foundNonEmpty {
			if h.EmptyLayer {
				continue
			}
			foundNonEmpty = true
		}

		if !h.EmptyLayer {
			continue
		}

		// Detect CMD instruction in base image
		if strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)  CMD") ||
			strings.HasPrefix(h.CreatedBy, "CMD") { // BuildKit
			baseImageIndex = i
			break
		}
	}

	if baseImageIndex == -1 {
		return -1
	}

	nonEmptyIndex := 0
	for i := 0; i <= baseImageIndex; i++ {
		if histories[i].EmptyLayer {
			continue
		}
		nonEmptyIndex += 1
	}

	return nonEmptyIndex
}
