package main

import (
	"log"
	"net/http"

	"github.com/gogo/protobuf/plugin/unmarshal"
	"github.com/gogo/protobuf/version"
)

func main() {
	print(version.AtLeast("v1.2.3"))
	unmarshal.NewUnmarshal()

	// Test stdlib
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}
