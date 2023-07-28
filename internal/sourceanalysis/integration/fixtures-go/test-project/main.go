package main

import (
	"github.com/gogo/protobuf/plugin/unmarshal"
	"github.com/gogo/protobuf/version"
	"github.com/ipfs/go-bitfield"
)

func main() {
	print(version.AtLeast("v1.2.3"))
	unmarshal.NewUnmarshal()

	bitfield.NewBitfield(14)
}
