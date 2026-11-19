package containers

import "strings"

// reference is an image reference taken apart: "docker.io/library/mariadb:11.4.13" is the
// repository "docker.io/library/mariadb" with the tag "11.4.13".
type reference struct {
	repo   string // registry and path, fully qualified
	tag    string
	digest string // "sha256:..." when the reference pins one
}

// parseReference reads a reference the way a container runtime does and fills in what Docker
// leaves out: Docker shows "gitea/gitea:1.23.6" and "redis" where Podman shows
// "docker.io/gitea/gitea:1.23.6" and "docker.io/library/redis:latest". The server compares
// images across machines, so both must come out the same. The rules are splitDockerDomain's in
// github.com/distribution/reference (normalize.go, v0.6.0).
func parseReference(s string) reference {
	var ref reference
	name := s
	if at := strings.IndexByte(name, '@'); at >= 0 {
		name, ref.digest = name[:at], name[at+1:]
	}
	// A colon after the last slash starts the tag; one before it belongs to "host:port".
	if colon := strings.LastIndexByte(name, ':'); colon > strings.LastIndexByte(name, '/') {
		name, ref.tag = name[:colon], name[colon+1:]
	}

	first, rest, found := strings.Cut(name, "/")
	switch {
	case !found:
		ref.repo = "docker.io/library/" + name
	case first == "index.docker.io":
		ref.repo = "docker.io/" + rest // Docker Hub's old name
	case first == "localhost", strings.ContainsAny(first, ".:"), strings.ToLower(first) != first:
		ref.repo = name // the first part is a registry already
	default:
		ref.repo = "docker.io/" + name
	}
	if hub, ok := strings.CutPrefix(ref.repo, "docker.io/"); ok && !strings.Contains(hub, "/") {
		ref.repo = "docker.io/library/" + hub
	}
	return ref
}

// String is the fully qualified reference. One that names neither a tag nor a digest means
// "latest" to every runtime, so it says so. A reference that was complete comes out unchanged:
// a digest gets no tag added, and "localhost/app:current" stays what it is.
func (r reference) String() string {
	s := r.repo
	switch {
	case r.tag != "":
		s += ":" + r.tag
	case r.digest == "":
		s += ":latest"
	}
	if r.digest != "" {
		s += "@" + r.digest
	}
	return s
}

// imageID reports whether configured is not a name at all but the ID of the image (or the
// start of it), as after "docker run 284e08721b32". id is the ID the runtime gives for the
// container's image.
func imageID(configured, id string) bool {
	hex := strings.TrimPrefix(configured, "sha256:")
	if hex == "" || strings.Trim(hex, "0123456789abcdef") != "" {
		return false
	}
	return strings.HasPrefix(strings.TrimPrefix(id, "sha256:"), hex)
}

// infraImage reports whether an image only holds a pod together: Kubernetes' "pause" image
// under any registry, and "localhost/podman-pause", which Podman builds for its pods up to at
// least 5.4, the version in Debian 13 (pkg/specgen/generate/pause_image.go there).
func infraImage(ref reference) bool {
	base := ref.repo[strings.LastIndexByte(ref.repo, '/')+1:]
	return base == "pause" || strings.HasSuffix(base, "-pause")
}
