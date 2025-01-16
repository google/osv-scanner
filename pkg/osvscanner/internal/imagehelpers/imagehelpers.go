package imagehelpers

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/google/osv-scanner/pkg/reporter"
)

func ExportDockerImage(r reporter.Reporter, dockerImageName string) (string, error) {
	// Skip saving if the file is already a tar archive.
	if strings.Contains(dockerImageName, ".tar") {
		if _, err := os.Stat(dockerImageName); err == nil {
			return dockerImageName, nil
		}
	}

	tempImageFile, err := os.CreateTemp("", "docker-image-*.tar")
	if err != nil {
		r.Errorf("Failed to create temporary file: %s\n", err)
		return "", err
	}

	err = tempImageFile.Close()
	if err != nil {
		return "", err
	}

	// Check if image exists locally, if not, pull from the cloud.
	r.Infof("Checking if docker image (%q) exists locally...\n", dockerImageName)
	cmd := exec.Command("docker", "images", "-q", dockerImageName)
	output, err := cmd.Output()
	if err != nil || string(output) == "" {
		r.Infof("Image not found locally, pulling docker image (%q)...\n", dockerImageName)
		err = runCommandLogError(r, "docker", "pull", "-q", dockerImageName)
		if err != nil {
			return "", fmt.Errorf("failed to pull container image: %w", err)
		}
	}

	r.Infof("Saving docker image (%q) to temporary file...\n", dockerImageName)
	err = runCommandLogError(r, "docker", "save", "-o", tempImageFile.Name(), dockerImageName)
	if err != nil {
		return "", err
	}

	return tempImageFile.Name(), nil
}

func runCommandLogError(r reporter.Reporter, name string, args ...string) error {
	cmd := exec.Command(name, args...)

	// Get stderr for debugging when docker fails
	stderr, err := cmd.StderrPipe()
	if err != nil {
		r.Errorf("Failed to get stderr: %s\n", err)
		return err
	}

	err = cmd.Start()
	if err != nil {
		r.Errorf("Failed to run docker command (%q): %s\n", cmd.String(), err)
		return err
	}
	// This has to be captured before cmd.Wait() is called, as cmd.Wait() closes the stderr pipe.
	var stderrLines []string
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		stderrLines = append(stderrLines, scanner.Text())
	}

	err = cmd.Wait()
	if err != nil {
		r.Errorf("Docker command exited with code (%q): %d\nSTDERR:\n", cmd.String(), cmd.ProcessState.ExitCode())
		for _, line := range stderrLines {
			r.Errorf("> %s\n", line)
		}

		return errors.New("failed to run docker command")
	}

	return nil
}
