// Package imagehelpers provides helper functions for working with container images.
package imagehelpers

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/imodels/results"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/opencontainers/go-digest"
)

func BuildImageMetadata(scanResults *results.ScanResults) *models.ImageMetadata {
	if scanResults.ImageMetadata == nil {
		return nil
	}

	layerMetadata := make([]models.LayerMetadata, 0, len(scanResults.ImageMetadata.GetLayerMetadata()))
	for _, cl := range scanResults.ImageMetadata.GetLayerMetadata() {
		layerMetadata = append(layerMetadata, models.LayerMetadata{
			DiffID:         digest.Digest(cl.GetDiffId()),
			Command:        cl.GetCommand(),
			IsEmpty:        cl.GetIsEmpty(),
			BaseImageIndex: int(cl.GetBaseImageIndex()),
		})
	}

	baseImages := make([][]models.BaseImageDetails, 0, len(scanResults.ImageMetadata.GetBaseImageChains()))

	for _, chain := range scanResults.ImageMetadata.GetBaseImageChains() {
		baseImageChain := make([]models.BaseImageDetails, 0, len(chain.GetBaseImages()))
		for _, imgs := range chain.GetBaseImages() {
			baseImageChain = append(baseImageChain, models.BaseImageDetails{
				Name: imgs.GetRepository(),
			})
		}
		baseImages = append(baseImages, baseImageChain)
	}

	imgMetadata := models.ImageMetadata{
		OS:            scanResults.ImageMetadata.GetOsInfo()["PRETTY_NAME"],
		LayerMetadata: layerMetadata,
		BaseImages:    baseImages,
	}

	return &imgMetadata
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
