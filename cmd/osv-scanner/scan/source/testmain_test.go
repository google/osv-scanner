package source_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan/source"
	"github.com/google/osv-scanner/v2/internal/clients/clientimpl/localmatcher"
	"github.com/google/osv-scanner/v2/internal/testdb"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestMain(m *testing.M) {
	// ensure a git repository doesn't already exist in the fixtures directory,
	// in case we didn't get a chance to clean-up properly in the last run
	os.RemoveAll("./fixtures/.git")

	// Temporarily make the fixtures folder a git repository to prevent gitignore files messing with tests.
	_, err := git.PlainInit("./fixtures", false)
	if err != nil {
		panic(err)
	}

	// localmatcher.ZippedDBRemoteHost = testdb.NewZipDBCacheServer().URL
	localmatcher.ZippedDBRemoteHost = testdb.NewZipDBCherryPickServer(map[string][]string{
		"RubyGems":  {},
		"Alpine":    {
			"CVE-2016-9840",
			"CVE-2016-9841",
			"CVE-2016-9842",
			"CVE-2016-9843",
			"CVE-2018-25032",
			"CVE-2022-37434",
			"CVE-2025-26519",
		},
		"Packagist": {},
		"Debian":    {},
		"Go": {
			"GO-2022-0452",
			"GHSA-f3fp-gc8g-vw66",
			"GO-2023-1683",
			"GHSA-g2j6-57v7-gm8c",
			"GO-2024-3110",
			"GHSA-jfvp-7x6p-h2pv",
			"GO-2023-1682",
			"GHSA-m8cg-xc2p-r3fc",
			"GO-2022-0274",
			"GHSA-v95c-p5hm-xq8f",
			"GO-2023-1627",
			"GHSA-vpvm-3wq2-2wvm",
			"GO-2024-2491",
			"GHSA-xr7r-f8xq-vfvv",
			"GO-2022-0493",
			"GHSA-p782-xgp4-8hr8",
		},
		"Maven":    {},
		"npm":      {"GHSA-whgm-jr23-g3j9"},
		"OSS-Fuzz": {},
	}).URL

	slog.SetDefault(slog.New(testlogger.New()))
	testcmd.CommandsUnderTest = []cmd.CommandBuilder{source.Command}
	m.Run()

	testutility.CleanSnapshots(m)

	os.RemoveAll("./fixtures/.git")
}
