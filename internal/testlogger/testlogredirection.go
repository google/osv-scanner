package testlogger

import (
	"bufio"
	"bytes"
	"runtime"
	"strings"
)

func getCallerInstance() string {
	var buf [8192]byte
	runtime.Stack(buf[:], false)
	n := runtime.Stack(buf[:], false)
	sc := bufio.NewScanner(bytes.NewReader(buf[:n]))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "testing.tRunner(") {
			return sc.Text()
		}
	}

	panic("no caller found in stack, recursed too deep?")
}
