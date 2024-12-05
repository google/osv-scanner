package scanners_test

// func Test_scanGit(t *testing.T) {
// 	t.Parallel()

// 	type args struct {
// 		r       reporter.Reporter
// 		repoDir string
// 	}
// 	tests := []struct {
// 		name    string
// 		args    args
// 		wantErr bool
// 		wantPkg []imodels.ScannedPackage
// 	}{
// 		{
// 			name: "Example Git repo",
// 			args: args{
// 				r:       &reporter.VoidReporter{},
// 				repoDir: "fixtures/example-git",
// 			},
// 			wantErr: false,
// 			wantPkg: []imodels.ScannedPackage{
// 				{
// 					Commit: "862ac4bd2703b622e85f29f55a2fd8cd6caf8182",
// 					Source: models.SourceInfo{
// 						Path: "fixtures/example-git",
// 						Type: "git",
// 					},
// 				},
// 			},
// 		},
// 	}

// 	err := os.Rename("fixtures/example-git/git-hidden", "fixtures/example-git/.git")
// 	if err != nil {
// 		t.Errorf("can't find git-hidden folder")
// 	}

// 	for _, tt := range tests {
// 		pkg, err := scanners.ScanGit(tt.args.r, tt.args.repoDir)
// 		if (err != nil) != tt.wantErr {
// 			t.Errorf("scanGit() error = %v, wantErr %v", err, tt.wantErr)
// 		}
// 		if !cmp.Equal(tt.wantPkg, pkg) {
// 			t.Errorf("scanGit() package = %v, wantPackage %v", pkg, tt.wantPkg)
// 		}
// 	}

// 	err = os.Rename("fixtures/example-git/.git", "fixtures/example-git/git-hidden")
// 	if err != nil {
// 		t.Errorf("can't find .git folder")
// 	}
// }
