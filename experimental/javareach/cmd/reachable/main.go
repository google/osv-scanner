package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/osv-scanner/experimental/javareach"
)

func main() {
	flag.Parse()
	for _, filename := range flag.Args() {
		reader, err := os.Open(filename)
		if err != nil {
			log.Printf("failed to open %s: %v", filename, err)
			continue
		}
		err = EnumerateReachability(reader)
		if err != nil {
			log.Printf("failed to enumerate reachability for %s: %v", filename, err)
		}
	}
}

// TODO:
//   - Transitively resolve dependencies and download dependent .jar files.
//   - Detect uses of reflection
//   - See if we should do a finer grained analysis to only consider referenced
//     classes where a method is called/referenced.
func EnumerateReachability(r io.Reader) error {
	cf, err := javareach.ParseClass(r)
	if err != nil {
		return err
	}

	thisClass, err := cf.ConstantPoolClass(int(cf.ThisClass))
	if err != nil {
		return err
	}
	fmt.Printf("this class: %s\n", thisClass)

	for i, cp := range cf.ConstantPool {
		if int(cf.ThisClass) == i {
			// Don't consider the this class itself.
			continue
		}

		if cp.Type() == javareach.ConstantKindClass {
			class, err := cf.ConstantPoolClass(i)
			if err != nil {
				return err
			}
			fmt.Printf("class: %s\n", class)
		}
	}

	return nil
}
