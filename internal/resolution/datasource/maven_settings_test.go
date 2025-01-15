package datasource_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/resolution/datasource"
	"github.com/google/osv-scanner/internal/testutility"
)

func TestParseMavenSettings(t *testing.T) {
	t.Setenv("MAVEN_SETTINGS_TEST_USR", "UsErNaMe")
	t.Setenv("MAVEN_SETTINGS_TEST_PWD", "P455W0RD")
	t.Setenv("MAVEN_SETTINGS_TEST_SID", "my-cool-server")
	t.Setenv("MAVEN_SETTINGS_TEST_NIL", "")
	s := datasource.ParseMavenSettings("./fixtures/maven_settings/settings.xml")
	testutility.NewSnapshot().MatchJSON(t, s)
}

func TestMakeMavenAuth(t *testing.T) {
	t.Parallel()
	globalSettings := datasource.MavenSettingsXML{
		Servers: []datasource.MavenSettingsXMLServer{
			{
				ID:       "global",
				Username: "global-user",
				Password: "global-pass",
			},
			{
				ID:       "overwrite1",
				Username: "original-user",
				Password: "original-pass",
			},
			{
				ID:       "overwrite2",
				Username: "user-to-be-deleted",
				// no password
			},
		},
	}
	userSettings := datasource.MavenSettingsXML{
		Servers: []datasource.MavenSettingsXMLServer{
			{
				ID:       "user",
				Username: "user",
				Password: "pass",
			},
			{
				ID:       "overwrite1",
				Username: "new-user",
				Password: "new-pass",
			},
			{
				ID: "overwrite2",
				// no username
				Password: "lone-password",
			},
		},
	}

	mAuth := datasource.MakeMavenAuth(globalSettings, userSettings)
	testutility.NewSnapshot().MatchJSON(t, mAuth)
}
