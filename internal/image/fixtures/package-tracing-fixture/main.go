package main

import (
	"os"

	"github.com/BurntSushi/toml"
)

func main() {
	toml.NewEncoder(os.Stdout)
}
