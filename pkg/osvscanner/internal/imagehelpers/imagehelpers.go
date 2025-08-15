// Package imagehelpers provides helper functions for working with container images.
package imagehelpers

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	"github.com/google/osv-scanner/v2/internal/clients/clientinterfaces"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
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
func ExportDockerImage(ctx context.Context, dockerImageName string) (string, error) {
	tempImageFile, err := os.CreateTemp("", "docker-image-*.tar")
	if err != nil {
		cmdlogger.Errorf("Failed to create temporary file: %s", err)
		return "", err
	}

	err = tempImageFile.Close()
	if err != nil {
		_ = os.RemoveAll(tempImageFile.Name())

		return "", err
	}

	// Check if image exists locally, if not, pull from the cloud.
	cmdlogger.Infof("Checking if docker image (%q) exists locally...", dockerImageName)
	// TODO: Pass through context here.
	cmd := exec.CommandContext(ctx, "docker", "images", "-q", dockerImageName)
	output, err := cmd.Output()
	if err != nil || string(output) == "" {
		cmdlogger.Infof("Image not found locally, pulling docker image (%q)...", dockerImageName)
		err = runCommandLogError(ctx, "docker", "pull", "-q", dockerImageName)
		if err != nil {
			_ = os.RemoveAll(tempImageFile.Name())

			return "", fmt.Errorf("failed to pull container image: %w", err)
		}
	}

	cmdlogger.Infof("Saving docker image (%q) to temporary file...", dockerImageName)
	err = runCommandLogError(ctx, "docker", "save", "-o", tempImageFile.Name(), dockerImageName)
	if err != nil {
		_ = os.RemoveAll(tempImageFile.Name())

		return "", err
	}

	return tempImageFile.Name(), nil
}

func runCommandLogError(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)

	// Get stderr for debugging when docker fails
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cmdlogger.Errorf("Failed to get stderr: %s", err)
		return err
	}

	err = cmd.Start()
	if err != nil {
		cmdlogger.Errorf("Failed to run docker command (%q): %s", cmd.String(), err)
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
		cmdlogger.Errorf("Docker command exited with code (%q): %d\nSTDERR:", cmd.String(), cmd.ProcessState.ExitCode())
		for _, line := range stderrLines {
			cmdlogger.Errorf("> %s", line)
		}

		return errors.New("failed to run docker command")
	}

	return nil
}
