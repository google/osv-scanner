package helper

import (
	"net"
	"testing"
)

func TestNewHTMLServerBindsToLoopback(t *testing.T) {
	t.Parallel()

	server := newHTMLServer("report.html", "8000")
	host, port, err := net.SplitHostPort(server.Addr)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q): %v", server.Addr, err)
	}
	if port != "8000" {
		t.Errorf("server port = %q, want %q", port, "8000")
	}

	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Errorf("server host = %q, want a loopback address", host)
	}
}
