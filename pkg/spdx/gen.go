//go:generate go run .
//go:build exclude
// +build exclude

package main

import (
	"encoding/json"
	"fmt"
	"go/format"
	"io/ioutil"
	"net/http"
	"strings"
)

type License struct {
	SPDXID string `json:"licenseId"`
}

func main() {
	resp, err := http.Get("https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var licenseList struct {
		Licenses []License `json:"licenses"`
	}
	err = json.Unmarshal(body, &licenseList)
	if err != nil {
		panic(err)
	}

	output := "package spdx\nvar IDs = map[string]bool{\n"
	for _, license := range licenseList.Licenses {
		output += fmt.Sprintf("%q: true,\n", strings.ToLower(license.SPDXID))
	}
	output += "}"
	formatted, err := format.Source([]byte(output))
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("licenses.go", formatted, 0644)
	if err != nil {
		panic(err)
	}
}
