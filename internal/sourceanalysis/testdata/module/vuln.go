package main

import (
	"encoding/pem"
	"fmt"

	"github.com/tidwall/gjson"
	"golang.org/x/text/language"
)

func main() {
	fmt.Println("hello")
	language.Parse("")
	gjson.Result{}.Get("")
	_, _ = pem.Decode([]byte("test"))
}
