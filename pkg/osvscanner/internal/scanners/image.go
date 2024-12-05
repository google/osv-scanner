package scanners

// func ScanImage(r reporter.Reporter, path string) ([]imodels.ScannedPackage, error) {
// 	scanResults, err := image.ScanImage(r, path)
// 	if err != nil {
// 		return []imodels.ScannedPackage{}, err
// 	}

// 	packages := make([]imodels.ScannedPackage, 0)

// 	for _, l := range scanResults.Lockfiles {
// 		for _, pkgDetail := range l.Packages {
// 			packages = append(packages, imodels.ScannedPackage{
// 				Name:        pkgDetail.Name,
// 				Version:     pkgDetail.Version,
// 				Commit:      pkgDetail.Commit,
// 				Ecosystem:   pkgDetail.Ecosystem,
// 				DepGroups:   pkgDetail.DepGroups,
// 				ImageOrigin: pkgDetail.ImageOrigin,
// 				Source: models.SourceInfo{
// 					Path: path + ":" + l.FilePath,
// 					Type: "docker",
// 				},
// 			})
// 		}
// 	}

// 	return packages, nil
// }

// func ScanDockerImage(r reporter.Reporter, dockerImageName string) ([]imodels.ScannedPackage, error) {
// 	tempImageFile, err := os.CreateTemp("", "docker-image-*.tar")
// 	if err != nil {
// 		r.Errorf("Failed to create temporary file: %s\n", err)
// 		return nil, err
// 	}

// 	err = tempImageFile.Close()
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer os.Remove(tempImageFile.Name())

// 	r.Infof("Pulling docker image (%q)...\n", dockerImageName)
// 	err = runCommandLogError(r, "docker", "pull", "-q", dockerImageName)
// 	if err != nil {
// 		return nil, err
// 	}

// 	r.Infof("Saving docker image (%q) to temporary file...\n", dockerImageName)
// 	err = runCommandLogError(r, "docker", "save", "-o", tempImageFile.Name(), dockerImageName)
// 	if err != nil {
// 		return nil, err
// 	}

// 	r.Infof("Scanning image...\n")
// 	packages, err := ScanImage(r, tempImageFile.Name())
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Modify the image path to be the image name, rather than the temporary file name
// 	for i := range packages {
// 		_, internalPath, _ := strings.Cut(packages[i].Source.Path, ":")
// 		packages[i].Source.Path = dockerImageName + ":" + internalPath
// 	}

// 	return packages, nil
// }

// func runCommandLogError(r reporter.Reporter, name string, args ...string) error {
// 	cmd := exec.Command(name, args...)

// 	// Get stderr for debugging when docker fails
// 	stderr, err := cmd.StderrPipe()
// 	if err != nil {
// 		r.Errorf("Failed to get stderr: %s\n", err)
// 		return err
// 	}

// 	err = cmd.Start()
// 	if err != nil {
// 		r.Errorf("Failed to run docker command (%q): %s\n", cmd.String(), err)
// 		return err
// 	}
// 	// This has to be captured before cmd.Wait() is called, as cmd.Wait() closes the stderr pipe.
// 	var stderrLines []string
// 	scanner := bufio.NewScanner(stderr)
// 	for scanner.Scan() {
// 		stderrLines = append(stderrLines, scanner.Text())
// 	}

// 	err = cmd.Wait()
// 	if err != nil {
// 		r.Errorf("Docker command exited with code (%q): %d\nSTDERR:\n", cmd.String(), cmd.ProcessState.ExitCode())
// 		for _, line := range stderrLines {
// 			r.Errorf("> %s\n", line)
// 		}

// 		return errors.New("failed to run docker command")
// 	}

// 	return nil
// }
