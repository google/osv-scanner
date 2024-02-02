package datasource

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"gopkg.in/ini.v1"
)

type npmrcConfig struct {
	*ini.Section
}

func loadNpmrc(workdir string) (npmrcConfig, error) {
	// Find & parse the 4 npmrc files (builtin, global, user, project) + values set in environment variables
	// https://docs.npmjs.com/cli/v10/configuring-npm/npmrc
	// https://docs.npmjs.com/cli/v10/using-npm/config

	// project npmrc is always in ./.npmrc
	projectFile, _ := filepath.Abs(filepath.Join(workdir, ".npmrc"))
	builtinFile := builtinNpmrc()
	envVarOpts, _ := envVarNpmrc()

	opts := ini.LoadOptions{
		Loose:              true, // ignore missing files
		KeyValueDelimiters: "=",  // default delimiters are "=:", but npmrc uses : in some keys
	}
	// Make use of data overwriting to load the correct values
	fullNpmrc, err := ini.LoadSources(opts, builtinFile, projectFile, envVarOpts)
	if err != nil {
		return npmrcConfig{}, err
	}

	// user npmrc is either set as userconfig, or ${HOME}/.npmrc
	// though userconfig cannot be set in the user or global npmrcs
	var userFile string
	switch {
	case fullNpmrc.Section("").HasKey("userconfig"):
		userFile = os.ExpandEnv(fullNpmrc.Section("").Key("userconfig").String())
		// TODO: npm config replaces only ${VAR}, not $VAR
		// and if VAR is unset, it will leave the string as "${VAR}"
	default:
		homeDir, err := os.UserHomeDir()
		if err == nil { // only set userFile if homeDir exists
			userFile = filepath.Join(homeDir, ".npmrc")
		}
	}

	// reload the npmrc files with the user file included
	fullNpmrc, err = ini.LoadSources(opts, builtinFile, userFile, projectFile, envVarOpts)
	if err != nil {
		return npmrcConfig{}, err
	}

	var globalFile string
	// global npmrc is either set as globalconfig, prefix/etc/npmrc, ${PREFIX}/etc/npmrc
	// cannot be set within the global npmrc itself
	switch {
	case fullNpmrc.Section("").HasKey("globalconfig"):
		globalFile = os.ExpandEnv(fullNpmrc.Section("").Key("globalconfig").String())
	case fullNpmrc.Section("").HasKey("prefix"):
		prefix := os.ExpandEnv(fullNpmrc.Section("").Key("prefix").String())
		globalFile, _ = filepath.Abs(filepath.Join(prefix, "etc", "npmrc"))
	case os.Getenv("PREFIX") != "":
		globalFile, _ = filepath.Abs(filepath.Join(os.Getenv("PREFIX"), "etc", "npmrc"))
	default:
		globalFile = filepath.Join("/etc", "npmrc") // TODO: what should this be actually?
	}

	// return final joined config, with correct overriding order
	fullNpmrc, err = ini.LoadSources(opts, builtinFile, globalFile, userFile, projectFile, envVarOpts)
	if err != nil {
		return npmrcConfig{}, err
	}

	return npmrcConfig{fullNpmrc.Section("")}, nil
}

func envVarNpmrc() ([]byte, error) {
	// parse npm config settings that were set in environment variables,
	// returns a ini.Load()-able byte array of the values

	iniFile := ini.Empty()
	// npm config environment variables seem to be case-insensitive, interpreted in lowercase
	// get all the matching environment variables and their values
	const envPrefix = "npm_config_"
	for _, env := range os.Environ() {
		split := strings.SplitN(env, "=", 2)
		k := strings.ToLower(split[0])
		v := split[1]
		if s, ok := strings.CutPrefix(k, envPrefix); ok {
			if _, err := iniFile.Section("").NewKey(s, v); err != nil {
				return nil, err
			}
		}
	}
	var buf bytes.Buffer
	_, err := iniFile.WriteTo(&buf)

	return buf.Bytes(), err
}

func builtinNpmrc() string {
	// builtin is always at /path/to/npm/npmrc
	npmExec, err := exec.LookPath("npm")
	if err != nil {
		return ""
	}
	npmExec, err = filepath.EvalSymlinks(npmExec)
	if err != nil {
		return ""
	}
	npmrc := filepath.Join(filepath.Dir(npmExec), "..", "npmrc")
	npmrc, err = filepath.Abs(npmrc)
	if err != nil {
		return ""
	}

	return npmrc
}

type npmRegistryAuthInfo struct {
	authToken string
	auth      string
	username  string
	password  string
}

func (authInfo npmRegistryAuthInfo) addAuth(header http.Header) {
	switch {
	case authInfo.authToken != "":
		header.Set("Authorization", "Bearer "+authInfo.authToken)
	case authInfo.auth != "":
		header.Set("Authorization", "Basic "+authInfo.auth)
	case authInfo.username != "" && authInfo.password != "":
		// auth is base64-encoded "username:password"
		// password is stored already base64-encoded
		authBytes := []byte(authInfo.username + ":")
		b, err := base64.StdEncoding.DecodeString(authInfo.password)
		if err != nil {
			// TODO: npm seems to actually be quite lenient with invalid encodings
			panic(fmt.Sprintf("Unable to decode registry password: %v", err))
		}
		authBytes = append(authBytes, b...)
		auth := base64.StdEncoding.EncodeToString(authBytes)
		header.Set("Authorization", "Basic "+auth)
	}
}

type npmRegistryInfo struct {
	URL      string
	authInfo *npmRegistryAuthInfo
}

// create the http request to the registry api
// urlComponents should be (package) or (package, version)
func (info npmRegistryInfo) buildRequest(ctx context.Context, urlComponents ...string) (*http.Request, error) {
	for i := range urlComponents {
		urlComponents[i] = url.PathEscape(urlComponents[i])
	}
	reqURL, err := url.JoinPath(info.URL, urlComponents...)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	info.authInfo.addAuth(req.Header)

	return req, nil
}

type npmRegistries map[string]npmRegistryInfo

// create the http request to the corresponding npm registry api
// urlComponents should be (package) or (package, version)
func (r npmRegistries) buildRequest(ctx context.Context, urlComponents ...string) (*http.Request, error) {
	if len(urlComponents) == 0 {
		return nil, errors.New("no package specified in npm request")
	}
	// find the corresponding registryInfo for the package's scope
	pkg := urlComponents[0]
	scope := ""
	if strings.HasPrefix(pkg, "@") {
		scope, _, _ = strings.Cut(pkg, "/")
	}
	info, ok := r[scope]
	if !ok {
		// no specific rules for this scope, use the default scope
		info = r[""]
	}

	return info.buildRequest(ctx, urlComponents...)
}

func parseRegistryInfo(npmrc npmrcConfig) npmRegistries {
	infos := make(npmRegistries)                   // map of @scope to info
	auths := make(map[string]*npmRegistryAuthInfo) // map of host url to auth

	getOrCreateAuth := func(host string) *npmRegistryAuthInfo {
		host, _ = strings.CutSuffix(host, "/")
		if authInfo, ok := auths[host]; ok {
			return authInfo
		}
		auths[host] = &npmRegistryAuthInfo{}

		return auths[host]
	}

	makeRegistryInfo := func(fullURL string) npmRegistryInfo {
		u, err := url.Parse(fullURL)
		if err != nil {
			panic(fmt.Sprintf("Error parsing url %s: %v", fullURL, err))
		}

		return npmRegistryInfo{
			URL:      fullURL,
			authInfo: getOrCreateAuth(u.Host),
		}
	}

	// set the default registry
	infos[""] = makeRegistryInfo("https://registry.npmjs.org")
	// Regexes for matching the scope/host in npmrc keys
	var (
		urlRegex       = cachedregexp.MustCompile(`^(@.*):registry$`)
		authTokenRegex = cachedregexp.MustCompile(`^//(.*):_authToken$`)
		authRegex      = cachedregexp.MustCompile(`^//(.*):_auth$`)
		usernameRegex  = cachedregexp.MustCompile(`^//(.*):username$`)
		passwordRegex  = cachedregexp.MustCompile(`^//(.*):_password$`)
	)

	for _, k := range npmrc.Keys() {
		name := k.Name()
		value := os.ExpandEnv(k.String())
		// TODO: npm config replaces only ${VAR}, not $VAR
		// and if VAR is unset, it will leave the string as "${VAR}"
		switch {
		case name == "registry":
			infos[""] = makeRegistryInfo(value)
		case urlRegex.MatchString(name):
			scope := urlRegex.FindStringSubmatch(name)[1]
			infos[scope] = makeRegistryInfo(value)
		case authTokenRegex.MatchString(name):
			u := authTokenRegex.FindStringSubmatch(name)[1]
			info := getOrCreateAuth(u)
			info.authToken = value
		case authRegex.MatchString(name):
			u := authRegex.FindStringSubmatch(name)[1]
			info := getOrCreateAuth(u)
			info.auth = value
		case usernameRegex.MatchString(name):
			u := usernameRegex.FindStringSubmatch(name)[1]
			info := getOrCreateAuth(u)
			info.username = value
		case passwordRegex.MatchString(name):
			u := passwordRegex.FindStringSubmatch(name)[1]
			info := getOrCreateAuth(u)
			info.password = value
		}
	}

	return infos
}
