package main

import (
	"context"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/google/osv-scanner/v2/internal/clients/clientimpl/localmatcher"
	"github.com/google/osv-scanner/v2/internal/testdb"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

// muffledHandler eats certain log messages to reduce noise in the test output
type muffledHandler struct {
	slog.TextHandler
}

func (c *muffledHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level < slog.LevelError {
		// todo: work with the osv-scalibr team to see if we can reduce these
		for _, prefix := range []string{
			"Starting filesystem walk for root:",
			"End status: ",
			"Neither CPE nor PURL found for package",
			"Invalid PURL",
			"os-release[ID] not set, fallback to",
			"VERSION_ID not set in os-release",
			"osrelease.ParseOsRelease(): file does not exist",
		} {
			if strings.HasPrefix(record.Message, prefix) {
				return nil
			}
		}
	}

	return c.TextHandler.Handle(ctx, record)
}

func newMuffledHandler(w io.Writer) *muffledHandler {
	return &muffledHandler{TextHandler: *slog.NewTextHandler(w, nil)}
}

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(newMuffledHandler(log.Writer())))

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
		"Alpine":    {"CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2018-25032", "CVE-2022-37434"},
		"Packagist": {},
		"Debian": {
			"CVE-2018-0501",
			"CVE-2019-3462",
			"DSA-4808-1",
			"DSA-4685-1",
			"CVE-2022-3715",
			"CVE-2016-2781",
			"CVE-2024-0684",
			"DLA-3482-1",
			"DSA-5147-1",
			"DLA-3022-1",
			"DSA-4535-1",
			"CVE-2019-5188",
			"CVE-2022-1304",
			"DLA-3910-1",
			"DSA-5122-1",
			"CVE-2017-0379",
			"CVE-2017-7526",
			"CVE-2018-0495",
			"CVE-2019-13627",
			"CVE-2021-33560",
			"CVE-2021-40528",
			"CVE-2024-2236",
			"CVE-2017-10790",
			"CVE-2018-6003",
			"CVE-2021-46848",
			"DLA-3263-1",
			"CVE-2016-3709",
			"CVE-2016-9318",
			"CVE-2017-0663",
			"CVE-2017-15412",
			"CVE-2017-16931",
			"CVE-2017-16932",
			"CVE-2017-18258",
			"CVE-2017-5130",
			"CVE-2017-7375",
			"CVE-2017-7376",
			"CVE-2017-8872",
			"CVE-2017-9047",
			"CVE-2017-9048",
			"CVE-2017-9049",
			"CVE-2017-9050",
			"CVE-2018-14404",
			"CVE-2018-14567",
			"CVE-2019-19956",
			"CVE-2019-20388",
			"CVE-2020-7595",
			"CVE-2021-3516",
			"CVE-2021-3517",
			"CVE-2021-3518",
			"CVE-2021-3537",
			"CVE-2021-3541",
			"CVE-2022-2309",
			"CVE-2022-23308",
			"DSA-5142-1",
			"DSA-5271-1",
			"CVE-2022-49043",
			"DSA-5391-1",
			"CVE-2024-25062",
			"DLA-3012-1",
			"DLA-3172-1",
			"DLA-3405-1",
			"DLA-3878-1",
			"CVE-2018-0732",
			"CVE-2018-0734",
			"CVE-2018-0735",
			"CVE-2018-5407",
			"CVE-2019-1543",
			"DSA-4539-1",
			"CVE-2019-1549",
			"DSA-4855-1",
			"DSA-4661-1",
			"DSA-4807-1",
			"DSA-4875-1",
			"CVE-2021-3450",
			"DSA-4963-1",
			"DSA-5103-1",
			"DSA-5139-1",
			"DSA-5169-1",
			"DSA-5343-1",
			"CVE-2022-2274",
			"CVE-2022-3358",
			"CVE-2022-3602",
			"CVE-2022-3786",
			"CVE-2022-3996",
			"CVE-2022-4203",
			"CVE-2023-0216",
			"CVE-2023-0217",
			"CVE-2023-0401",
			"DSA-5417-1",
			"CVE-2023-1255",
			"CVE-2023-2975",
			"CVE-2023-3446",
			"CVE-2023-3817",
			"DSA-5532-1",
			"CVE-2023-5678",
			"CVE-2023-6129",
			"CVE-2023-6237",
			"CVE-2024-0727",
			"CVE-2024-13176",
			"CVE-2024-2511",
			"CVE-2024-4603",
			"CVE-2024-4741",
			"CVE-2024-5535",
			"DSA-5764-1",
			"CVE-2024-9143",
			"DLA-3008-1",
			"DLA-3325-1",
			"DLA-3449-1",
			"DLA-3530-1",
			"DLA-3942-1",
			"DLA-3942-2",
			"DSA-4539-3",
			"CVE-2017-12837",
			"CVE-2017-12883",
			"CVE-2018-12015",
			"CVE-2018-18311",
			"CVE-2018-18312",
			"CVE-2018-18313",
			"CVE-2018-18314",
			"CVE-2018-6797",
			"CVE-2018-6798",
			"CVE-2018-6913",
			"CVE-2020-10543",
			"CVE-2020-10878",
			"CVE-2020-12723",
			"CVE-2020-16156",
			"CVE-2021-36770",
			"CVE-2023-31484",
			"CVE-2023-47038",
			"DLA-3926-1",
			"DLA-3072-1",
			"DLA-3189-1",
			"DLA-3316-1",
			"DLA-3422-1",
			"DLA-3600-1",
			"DLA-3651-1",
			"DLA-3764-1",
			"DSA-5135-1",
			"CVE-2017-17512",
			"CVE-2018-20482",
			"CVE-2023-39804",
			"DLA-3755-1",
			"DLA-3051-1",
			"DLA-3134-1",
			"DLA-3161-1",
			"DLA-3366-1",
			"DLA-3412-1",
			"DLA-3684-1",
			"DLA-3788-1",
			"DLA-3972-1",
			"DLA-4016-1",
			"CVE-2016-2779",
			"DSA-5055-1",
			"DSA-5650-1",
			"DLA-3782-1",
			"DSA-5123-1",
			"CVE-2024-3094",
			"CVE-2011-3374",
			"CVE-2019-18276",
			"CVE-2017-18018",
			"CVE-2018-6829",
			"CVE-2018-1000654",
			"CVE-2020-24977",
			"CVE-2024-34459",
			"CVE-2011-4116",
			"CVE-2022-48522",
			"CVE-2023-31486",
			"CVE-2005-2541",
			"CVE-2019-9923",
			"CVE-2021-20193",
			"CVE-2022-48303",
			"CVE-2018-7738",
			"CVE-2022-0563",
		},
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

	code := m.Run()

	testutility.CleanSnapshots(m)

	os.RemoveAll("./fixtures/.git")
	os.Exit(code)
}
