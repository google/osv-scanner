package main

import (
	"fmt"
	"log"

	jpatch "github.com/evanphx/json-patch"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

func main() {
	tf := unicode.BOMOverride(transform.Nop)
	src := []byte("hello, world")
	dst := make([]byte, len(src))
	nd, ns, err := tf.Transform(dst, src, true)
	fmt.Println(nd, ns, err)

	fmt.Println(uuid.NewV1())

	p, err := jpatch.DecodePatch([]byte(`[{ "op": "add", "path": "/a", "value": 1 }]`))
	if err != nil {
		log.Fatal(err)
	}
	doc, err := p.Apply([]byte(`{}`))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(doc))

}
