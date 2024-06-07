package grouper_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/grouper"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestGroupPackageByPURL_ShouldUnifyPackages(t *testing.T) {
	t.Parallel()
	input := []models.PackageSource{
		{
			Source: models.SourceInfo{
				Path: "/dir/lockfile.xml",
				Type: "",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(lockfile.MavenEcosystem),
					},
					Vulnerabilities: []models.Vulnerability{
						{ID: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
					DepGroups: []string{"build"},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(lockfile.MavenEcosystem),
					},
					Vulnerabilities: []models.Vulnerability{
						{ID: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(lockfile.MavenEcosystem),
					},
					Vulnerabilities: []models.Vulnerability{
						{ID: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:package-2",
						Ecosystem: string(lockfile.MavenEcosystem),
						Version:   "1.0.0",
					},
				},
			},
		},
		{
			Source: models.SourceInfo{
				Path: "/dir2/lockfile.json",
				Type: "",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(lockfile.MavenEcosystem),
					},
					Vulnerabilities: []models.Vulnerability{
						{ID: "GHSA-456"},
					},
					Groups: []models.GroupInfo{
						{
							IDs:     []string{"GHSA-456"},
							Aliases: []string{"GHSA-456"},
						},
					},
					DepGroups: []string{"test"},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:package-2",
						Ecosystem: string(lockfile.MavenEcosystem),
						Version:   "1.0.0",
					},
				},
			},
		},
	}

	result, errors := grouper.GroupByPURL(input)

	expected := map[string]models.PackageVulns{
		"pkg:maven/foo.bar/the-first-package@1.0.0": {
			Package: models.PackageInfo{
				Name:      "foo.bar:the-first-package",
				Version:   "1.0.0",
				Ecosystem: string(lockfile.MavenEcosystem),
			},
			Vulnerabilities: []models.Vulnerability{
				{ID: "GHSA-456"},
			},
			Groups: []models.GroupInfo{
				{
					IDs:     []string{"GHSA-456"},
					Aliases: []string{"GHSA-456"},
				},
			},
			DepGroups: []string{"build", "test"},
		},
		"pkg:maven/foo.bar/package-2@1.0.0": {
			Package: models.PackageInfo{
				Name:      "foo.bar:package-2",
				Version:   "1.0.0",
				Ecosystem: string(lockfile.MavenEcosystem),
			},
		},
	}

	assert.Empty(t, errors)
	assert.Equal(t, expected, result)
}
