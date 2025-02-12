package imagehelpers

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scanner/v2/internal/clients/clientinterfaces"
	"github.com/google/osv-scanner/v2/pkg/models"
)

func BuildImageMetadata(img *image.Image, baseImageMatcher clientinterfaces.BaseImageMatcher) (*models.ImageMetadata, error) {
	chainLayers, err := img.ChainLayers()
	if err != nil {
		// This is very unlikely, as if this would error we would have failed the initial scan
		return nil, err
	}
	m, err := osrelease.GetOSRelease(chainLayers[len(chainLayers)-1].FS())
	OS := "Unknown"
	if err == nil {
		OS = m["PRETTY_NAME"]
	}

	layerMetadata := []models.LayerMetadata{}
	for _, cl := range chainLayers {
		layerMetadata = append(layerMetadata, models.LayerMetadata{
			DiffID:  cl.Layer().DiffID(),
			Command: cl.Layer().Command(),
			IsEmpty: cl.Layer().IsEmpty(),
		})
	}

	var baseImages [][]models.BaseImageDetails

	if baseImageMatcher != nil {
		baseImages, err = baseImageMatcher.MatchBaseImages(context.Background(), layerMetadata)
		if err != nil {
			return nil, fmt.Errorf("failed to query for container base images: %w", err)
		}
	} else {
		baseImages = [][]models.BaseImageDetails{
			// The base image at index 0 is a placeholder representing your image, so always empty
			// This is the case even if your image is a base image, in that case no layers point to index 0
			{},
		}
	}

	imgMetadata := models.ImageMetadata{
		OS:            OS,
		LayerMetadata: layerMetadata,
		BaseImages:    baseImages,
	}

	return &imgMetadata, nil
}

// ExportDockerImage will execute the docker binary to export an image to a temporary file in the tarball OCI format.
//
// If ExportDockerImage does not error, the temporary file needs to be cleaned up by the caller, otherwise, it will be
// cleaned automatically by this function.
//
// ExportDockerImage will first try to locate the image locally, and if not found, attempt to pull the image from the docker registry.
func ExportDockerImage(dockerImageName string) (string, error) {
	tempImageFile, err := os.CreateTemp("", "docker-image-*.tar")
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to create temporary file: %s\n", err))
		return "", err
	}

	err = tempImageFile.Close()
	if err != nil {
		_ = os.RemoveAll(tempImageFile.Name())

		return "", err
	}

	// Check if image exists locally, if not, pull from the cloud.
	slog.Info(fmt.Sprintf("Checking if docker image (%q) exists locally...\n", dockerImageName))
	cmd := exec.Command("docker", "images", "-q", dockerImageName)
	output, err := cmd.Output()
	if err != nil || string(output) == "" {
		slog.Info(fmt.Sprintf("Image not found locally, pulling docker image (%q)...\n", dockerImageName))
		err = runCommandLogError("docker", "pull", "-q", dockerImageName)
		if err != nil {
			_ = os.RemoveAll(tempImageFile.Name())

			return "", fmt.Errorf("failed to pull container image: %w", err)
		}
	}

	slog.Info(fmt.Sprintf("Saving docker image (%q) to temporary file...\n", dockerImageName))
	err = runCommandLogError("docker", "save", "-o", tempImageFile.Name(), dockerImageName)
	if err != nil {
		_ = os.RemoveAll(tempImageFile.Name())

		return "", err
	}

	return tempImageFile.Name(), nil
}

func runCommandLogError(name string, args ...string) error {
	cmd := exec.Command(name, args...)

	// Get stderr for debugging when docker fails
	stderr, err := cmd.StderrPipe()
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to get stderr: %s\n", err))
		return err
	}

	err = cmd.Start()
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to run docker command (%q): %s\n", cmd.String(), err))
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
		slog.Error(fmt.Sprintf("Docker command exited with code (%q): %d\nSTDERR:\n", cmd.String(), cmd.ProcessState.ExitCode()))
		for _, line := range stderrLines {
			slog.Error(fmt.Sprintf("> %s\n", line))
		}

		return errors.New("failed to run docker command")
	}

	return nil
}
