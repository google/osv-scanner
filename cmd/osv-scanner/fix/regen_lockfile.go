package fix

import (
	"os"
	"os/exec"
	"path/filepath"
)

func regenerateLockfileCmd(opts osvFixOptions) (*exec.Cmd, error) {
	// TODO: this is npm-specific and hacky
	// delete existing package-lock & node_modules directory to force npm to do a clean install
	dir := filepath.Dir(opts.Manifest)
	if err := os.RemoveAll(filepath.Join(dir, "package-lock.json")); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(filepath.Join(dir, "node_modules")); err != nil {
		return nil, err
	}
	// TODO: need to also remove node_modules/ in workspace packages

	c := exec.Command("npm", "install", "--package-lock-only")
	c.Dir = dir

	return c, nil
}
