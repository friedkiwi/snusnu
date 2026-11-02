package server

import (
	"errors"
	"net/http"
	"regexp"

	"golang.org/x/mod/semver"
)

const softwareNameHeader = "X-Snusnu-Software-Name"
const softwareVersionHeader = "X-Snusnu-Software-Version"

// Keep this in sync with sna_router/crates/snusnu-router/Cargo.toml. A test
// checks the manifest, so a router version bump cannot silently miss Go.
const latestSnaRouterVersion = "0.1.0"

type softwarePolicy struct {
	minimumVersion  string
	blockedVersions map[string]bool
}

// Change this code to retire an old first-party release or block one exact
// release. Unknown client names are allowed and never receive update notices.
var snaRouterPolicy = softwarePolicy{
	minimumVersion:  "0.0.0",
	blockedVersions: map[string]bool{},
}

var softwareToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var softwareVersionToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
var errSoftwareBlocked = errors.New("sna_router version is blocked; update the router")

type clientSoftware struct {
	name, version, updateVersion string
}

func inspectClientSoftware(r *http.Request) (clientSoftware, error) {
	name := r.Header.Get(softwareNameHeader)
	version := r.Header.Get(softwareVersionHeader)
	if name == "" && version == "" {
		return clientSoftware{name: "unknown", version: "unknown"}, nil // Older clients.
	}
	if !softwareToken.MatchString(name) || !softwareVersionToken.MatchString(version) {
		return clientSoftware{}, errors.New("invalid client software name or version")
	}
	client := clientSoftware{name: name, version: version}
	if name != "sna_router" {
		return client, nil
	}
	return evaluateSnaRouter(client, snaRouterPolicy, latestSnaRouterVersion)
}

func evaluateSnaRouter(client clientSoftware, policy softwarePolicy, latest string) (clientSoftware, error) {
	version := client.version
	current := "v" + version
	if !semver.IsValid(current) || semver.Canonical(current) != current {
		return clientSoftware{}, errors.New("invalid sna_router version")
	}
	if policy.blockedVersions[version] || semver.Compare(current, "v"+policy.minimumVersion) < 0 {
		return clientSoftware{}, errSoftwareBlocked
	}
	if semver.Compare(current, "v"+latest) < 0 {
		client.updateVersion = latest
	}
	return client, nil
}

func softwareErrorStatus(err error) int {
	if errors.Is(err, errSoftwareBlocked) {
		return http.StatusForbidden
	}
	return http.StatusBadRequest
}
