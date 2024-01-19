package datasource

import (
	"bytes"
	"encoding/gob"
	"time"
)

const cacheExpiry = 6 * time.Hour

func gobMarshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)

	err := enc.Encode(v)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func gobUnmarshal(b []byte, v any) error {
	dec := gob.NewDecoder(bytes.NewReader(b))
	return dec.Decode(v)
}
