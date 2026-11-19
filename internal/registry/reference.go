package registry

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// The grammar is the one container runtimes share, from github.com/distribution/reference
// (regexp.go and normalize.go, v0.6.0).
var (
	hostRE   = regexp.MustCompile(`^(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(?:\.(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*|\[[a-fA-F0-9:]+\])(?::[0-9]+)?$`)
	repoRE   = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)*$`)
	tagRE    = regexp.MustCompile(`^[\w][\w.-]{0,127}$`)
	digestRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}$`)
	idRE     = regexp.MustCompile(`^(?:sha256:)?[a-f0-9]{64}$`)
)

const (
	dockerHub    = "docker.io"
	dockerHubAPI = "registry-1.docker.io"
	maxRepoLen   = 255 // RepositoryNameTotalLengthMax upstream
)

// reference is an image reference taken apart the way a container runtime reads it.
type reference struct {
	host   string // "docker.io", "ghcr.io", "registry.example:5000"; empty for a bare image ID
	repo   string // "library/mariadb", "gitea/gitea"
	tag    string // empty when the reference names only a digest
	digest string // "sha256:..." when the reference pins one
}

// parseReference reads a reference as a runtime prints it: "mariadb:11.4",
// "docker.io/gitea/gitea:1.23.6", "ghcr.io/stryan/materia@sha256:...", "localhost/app:current".
func parseReference(s string) (reference, error) {
	if s == "" {
		return reference{}, errors.New("empty image reference")
	}
	if idRE.MatchString(s) {
		return reference{}, nil // an image ID: it names no registry and no repository
	}
	var ref reference
	name := s
	if at := strings.IndexByte(name, '@'); at >= 0 {
		name, ref.digest = name[:at], name[at+1:]
		if !digestRE.MatchString(ref.digest) {
			return reference{}, fmt.Errorf("image reference %q: the part after @ is not a digest", s)
		}
	}
	// A colon after the last slash starts the tag; one before it belongs to "host:port".
	if colon := strings.LastIndexByte(name, ':'); colon > strings.LastIndexByte(name, '/') {
		name, ref.tag = name[:colon], name[colon+1:]
		if !tagRE.MatchString(ref.tag) {
			return reference{}, fmt.Errorf("image reference %q: %q is not a tag", s, ref.tag)
		}
	}
	ref.host, ref.repo = splitHost(name)
	switch {
	case !hostRE.MatchString(ref.host):
		return reference{}, fmt.Errorf("image reference %q: %q is not a registry", s, ref.host)
	case !repoRE.MatchString(ref.repo) || len(ref.repo) > maxRepoLen:
		return reference{}, fmt.Errorf("image reference %q: %q is not a repository name", s, ref.repo)
	}
	if ref.tag == "" && ref.digest == "" {
		ref.tag = "latest" // what a runtime pulls when nothing is named
	}
	return ref, nil
}

// splitHost decides whether the first path element is a registry, as splitDockerDomain does
// upstream: it is one when it is "localhost", has a dot or a colon, or has an uppercase letter.
// Everything else is a repository on Docker Hub, where one-word names live under "library/".
func splitHost(name string) (host, repo string) {
	first, rest, found := strings.Cut(name, "/")
	switch {
	case !found:
		return dockerHub, "library/" + name
	case first == "index.docker.io" || first == dockerHubAPI:
		host, repo = dockerHub, rest
	case first == "localhost" || strings.ContainsAny(first, ".:") || strings.ToLower(first) != first:
		host, repo = first, rest
	default:
		host, repo = dockerHub, name
	}
	if host == dockerHub && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	return host, repo
}

// local reports whether no registry can be asked about this image. "localhost/..." is where
// Podman and Buildah put images built on the machine, an image ID names no registry, and a
// registry on a loopback address is the reporting machine's own, not one this server can reach.
func (r reference) local() bool {
	if r.host == "" {
		return true
	}
	host := r.host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// apiHost is where the registry's API answers. Docker Hub's is not the name in references.
func (r reference) apiHost() string {
	if r.host == dockerHub {
		return dockerHubAPI
	}
	return r.host
}

// name is the repository with its registry, for messages.
func (r reference) name() string { return r.host + "/" + r.repo }
