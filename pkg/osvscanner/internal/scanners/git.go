package scanners

// // Scan git repository. Expects repoDir to end with /
// func ScanGit(r reporter.Reporter, repoDir string) ([]imodels.ScannedPackage, error) {
// 	commit, err := getCommitSHA(repoDir)
// 	if err != nil {
// 		return nil, err
// 	}
// 	r.Infof("Scanning %s at commit %s\n", repoDir, commit)

// 	//nolint:prealloc // Not sure how many there will be in advance.
// 	var packages []imodels.ScannedPackage
// 	packages = append(packages, createCommitQueryPackage(commit, repoDir))

// 	submodules, err := getSubmodules(repoDir)
// 	if err != nil {
// 		return nil, err
// 	}

// 	for _, s := range submodules {
// 		r.Infof("Scanning submodule %s at commit %s\n", s.Path, s.Expected.String())
// 		packages = append(packages, createCommitQueryPackage(s.Expected.String(), path.Join(repoDir, s.Path)))
// 	}

// 	return packages, nil
// }

// func getCommitSHA(repoDir string) (string, error) {
// 	repo, err := git.PlainOpen(repoDir)
// 	if err != nil {
// 		return "", err
// 	}
// 	head, err := repo.Head()
// 	if err != nil {
// 		return "", err
// 	}

// 	return head.Hash().String(), nil
// }

// func getSubmodules(repoDir string) (submodules []*git.SubmoduleStatus, err error) {
// 	repo, err := git.PlainOpen(repoDir)
// 	if err != nil {
// 		return nil, err
// 	}
// 	worktree, err := repo.Worktree()
// 	if err != nil {
// 		return nil, err
// 	}
// 	ss, err := worktree.Submodules()
// 	if err != nil {
// 		return nil, err
// 	}
// 	for _, s := range ss {
// 		status, err := s.Status()
// 		if err != nil {
// 			continue
// 		}
// 		submodules = append(submodules, status)
// 	}

// 	return submodules, nil
// }
