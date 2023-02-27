package govulncheckshim

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/pkg/models"
)

func newTestClient(t *testing.T) *localSource {
	t.Helper()

	vulns := []models.Vulnerability{}
	entries, err := os.ReadDir("fixtures/client")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		file, err := os.Open(filepath.Join("fixtures/client", entry.Name()))
		if err != nil {
			t.Fatalf("failed to open test fixtures %s", err)
		}
		newVuln := models.Vulnerability{}
		err = json.NewDecoder(file).Decode(&newVuln)
		if err != nil {
			t.Fatalf("failed to parse test fixtures %s", err)
		}
		vulns = append(vulns, newVuln)
	}

	return newClient(vulns)
}

func TestGetByID(t *testing.T) {
	t.Parallel()

	type IDTestCases struct {
		ID          string
		ReturnValue *struct {
			Published string
		}
	}

	testCases := []IDTestCases{
		{
			ID: "GO-2021-0098",
			ReturnValue: &struct{ Published string }{
				Published: "2021-04-14",
			},
		},
		{
			ID: "GO-2022-0569",
			ReturnValue: &struct{ Published string }{
				Published: "2022-08-23",
			},
		},
		{
			ID: "GHSA-vc3p-29h2-gpcp",
			ReturnValue: &struct{ Published string }{
				Published: "2022-01-02",
			},
		},
		{
			ID:          "GO-1234-5678",
			ReturnValue: nil,
		},
	}

	client := newTestClient(t)
	for _, x := range testCases {
		res, err := client.GetByID(context.Background(), x.ID)
		if err != nil {
			t.Error(err)
		}
		if (x.ReturnValue == nil) != (res == nil) {
			t.Errorf("Expected %s, found %s", x.ReturnValue, res)
		}

		if res == nil {
			return
		}

		if res.Published.Format("2006-01-02") != x.ReturnValue.Published {
			t.Errorf("Expected %s, found %s", x.ReturnValue.Published, res.Published.Format("yyyy-mm-dd"))
		}
	}
}

func TestGetByAlias(t *testing.T) {
	t.Parallel()

	type AliasTestCases struct {
		Alias       string
		ReturnValue []struct {
			ID string
		}
	}

	testCases := []AliasTestCases{
		{
			Alias: "CVE-2021-44716",
			ReturnValue: []struct{ ID string }{
				{
					ID: "GHSA-vc3p-29h2-gpcp",
				},
			},
		},
		{
			Alias: "CVE-2021-21237",
			ReturnValue: []struct{ ID string }{
				// Order doesn't matter
				{
					ID: "GHSA-cx3w-xqmc-84g5",
				},
				{
					ID: "GO-2021-0098",
				},
			},
		},
		{
			Alias: "GHSA-cx3w-xqmc-84g5",
			ReturnValue: []struct{ ID string }{
				// If the alias is the ID, do not return the entry
				// TODO: Is this correct behavior?
				// {
				// 	ID: "GHSA-cx3w-xqmc-84g5",
				// },
				{
					ID: "GO-2021-0098",
				},
			},
		},
		{
			Alias:       "GO-1234-5678",
			ReturnValue: nil,
		},
	}

	client := newTestClient(t)
	for _, x := range testCases {
		res, err := client.GetByAlias(context.Background(), x.Alias)
		if err != nil {
			t.Error(err)
		}
		if (x.ReturnValue == nil) != (res == nil) {
			t.Errorf("Expected %v, found %v", x.ReturnValue, res)
		}

		if res == nil {
			return
		}

		if len(res) != len(x.ReturnValue) {
			t.Errorf("Expected %v, found %v", x.ReturnValue, res)
		}

		for i := range res {
			if res[i].ID != x.ReturnValue[i].ID {
				t.Errorf("Expected %s, found %s", x.ReturnValue[i].ID, res[i].ID)
			}
		}
	}
}

func TestGetByModule(t *testing.T) {
	t.Parallel()

	type ModuleTestCases struct {
		Module      string
		ReturnValue []struct {
			ID string
		}
	}

	testCases := []ModuleTestCases{
		{
			Module: "github.com/beego/beego",
			ReturnValue: []struct{ ID string }{
				{
					ID: "GO-2022-0569",
				},
			},
		},
		{
			Module: "github.com/git-lfs/git-lfs",
			ReturnValue: []struct{ ID string }{
				// Order doesn't matter
				{
					ID: "GHSA-cx3w-xqmc-84g5",
				},
				{
					ID: "GO-2021-0098",
				},
			},
		},
		{
			Module:      "golang.org/x/y/z",
			ReturnValue: nil,
		},
	}

	client := newTestClient(t)
	for _, x := range testCases {
		res, err := client.GetByModule(context.Background(), x.Module)
		if err != nil {
			t.Error(err)
		}
		if (x.ReturnValue == nil) != (res == nil) {
			t.Errorf("Expected %v, found %v", x.ReturnValue, res)
		}

		if res == nil {
			return
		}

		if len(res) != len(x.ReturnValue) {
			t.Errorf("Expected %v, found %v", x.ReturnValue, res)
		}

		for i := range res {
			if res[i].ID != x.ReturnValue[i].ID {
				t.Errorf("Expected %s, found %s", x.ReturnValue[i].ID, res[i].ID)
			}
		}
	}
}

func TestLastModifiedTime(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)
	clientLastModTime, err := client.LastModifiedTime(context.Background())
	if err != nil {
		t.Error(err)
	}

	// Last modified time in GHSA-vc3p-29h2-gpcp
	if clientLastModTime.Format("2006-01-02") != "2023-02-08" {
		t.Errorf("Expected %s, found %s", "2023-02-08", clientLastModTime.Format("2006-01-02"))
	}
}
