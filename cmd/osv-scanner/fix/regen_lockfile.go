package fix

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/pkg/reporter"
)

func regenerateLockfile(r reporter.Reporter, opts osvFixOptions) error {
	// TODO: this is npm-specific and hacky
	// delete existing package-lock & node_modules directory to force npm to do a clean install
	dir := filepath.Dir(opts.Manifest)
	if err := os.RemoveAll(filepath.Join(dir, "package-lock.json")); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
		return err
	}
	// TODO: need to also remove node_modules/ in workspace packages

	cmd := opts.RelockCmd
	if cmd == "" {
		cmd = "npm install --package-lock-only"
	}
	cmdParts := strings.Split(cmd, " ")
	c := exec.Command(cmdParts[0], cmdParts[1:]...) //nolint:gosec
	c.Dir = dir
	// ideally I'd have the reporter's stdout/stderr here...
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	r.Infof("Executing `%s`...\n", cmd)
	err := c.Run()
	if err != nil && opts.RelockCmd == "" {
		r.Warnf("Install failed. Trying again with `--legacy-peer-deps`...\n")
		cmdParts = append(cmdParts, "--legacy-peer-deps")
		c := exec.Command(cmdParts[0], cmdParts[1:]...) //nolint:gosec
		c.Dir = dir
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		err = c.Run()
	}

	return err
}
