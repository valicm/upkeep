// Package containers reports the containers that run on this machine: the image each one was
// started from and the digest that image was pulled as. It asks the runtime over its API socket
// and runs no command, so an agent that was given access to the socket needs no other privilege.
// Podman serves Docker's API too, which is why one set of calls covers both.
package containers

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/collect"
	"github.com/valicm/upkeep/internal/report"
)

// Config is this collector's part of the agent's configuration file:
//
//	[containers]
//	enabled = false                        # default true
//	sockets = ["/run/podman/podman.sock"]  # default: the usual places
type Config struct {
	Enabled *bool    `toml:"enabled"`
	Sockets []string `toml:"sockets"`
}

// socketTimeout bounds everything asked of one socket, so a runtime that hangs cannot hold up
// the rest of the report.
const socketTimeout = 45 * time.Second

// autoUpdateLabel is where Podman keeps a container's auto-update policy.
const autoUpdateLabel = "io.containers.autoupdate"

type collector struct {
	enabled    bool
	sockets    []string        // as configured; empty means candidates()
	candidates func() []string // where runtimes usually listen
	installed  func() string   // the runtime whose command is on this machine, "" for none
}

// New returns the collector.
func New(cfg Config) collect.Collector {
	return &collector{
		enabled:    cfg.Enabled == nil || *cfg.Enabled,
		sockets:    cfg.Sockets,
		candidates: func() []string { return usualSockets(os.Getenv("XDG_RUNTIME_DIR"), os.Getuid()) },
		installed:  installedRuntime,
	}
}

// installedRuntime names the container runtime whose command is installed, looking where
// packages put it: a service's PATH is not to be relied on.
func installedRuntime() string {
	for _, name := range []string{"podman", "docker"} {
		for _, dir := range []string{"/usr/bin", "/usr/local/bin", "/bin"} {
			if st, err := os.Stat(filepath.Join(dir, name)); err == nil && st.Mode().IsRegular() {
				return name
			}
		}
	}
	return ""
}

func (c *collector) Name() string { return "containers" }

// usualSockets lists where a runtime listens when nobody says otherwise: rootful Podman
// (Linux, then FreeBSD), this user's rootless Podman, Docker, this user's rootless Docker.
func usualSockets(runtimeDir string, uid int) []string {
	if runtimeDir == "" {
		runtimeDir = "/run/user/" + strconv.Itoa(uid)
	}
	return []string{
		"/run/podman/podman.sock",
		"/var/run/podman/podman.sock",
		filepath.Join(runtimeDir, "podman", "podman.sock"),
		"/var/run/docker.sock",
		filepath.Join(runtimeDir, "docker.sock"),
	}
}

// Collect asks every socket it finds. A machine can run Podman and Docker side by side, and
// both are reported.
func (c *collector) Collect(ctx context.Context, r *report.Report) error {
	if !c.enabled {
		return nil
	}
	paths, configured := c.sockets, true
	if len(paths) == 0 {
		paths, configured = c.candidates(), false
	}

	var found []report.Container
	var errs []error
	asked := map[string]bool{}      // sockets, by where they really are
	containers := map[string]bool{} // container IDs, across sockets
	for _, path := range paths {
		socket, err := locate(path)
		switch {
		case err != nil && configured:
			errs = append(errs, err)
			continue
		case err != nil:
			// Not there, or behind a directory this user may not enter: a machine without
			// that runtime. Only a socket somebody configured has to exist.
			continue
		case asked[socket]:
			continue // "/var/run" is "/run" on Linux, and podman-docker links Docker's path to Podman's
		}
		asked[socket] = true

		got, err := inspectAll(ctx, path)
		if err != nil {
			errs = append(errs, err)
		}
		for _, ct := range got {
			if !containers[ct.id] {
				containers[ct.id] = true
				found = append(found, ct.Container)
			}
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].Name != found[j].Name {
			return found[i].Name < found[j].Name
		}
		return found[i].Runtime < found[j].Runtime
	})
	r.Containers = append(r.Containers, found...)

	// The agent drops everything a collector found when the collector returns an error, so an
	// error is only for a run that found nothing. What went wrong beside the containers that
	// were found goes into the report with them.
	if len(found) == 0 {
		if !configured && len(asked) == 0 && len(errs) == 0 {
			// No socket anywhere, or none this user may get to. On a machine without a
			// runtime that is all there is to say. With one installed, its containers go
			// unseen and nobody would know: Podman's API socket is off until it is enabled,
			// and rootful Podman's own lies in a directory only root may enter.
			if runtime := c.installed(); runtime != "" {
				return fmt.Errorf("%s is installed but its API socket was not found (looked at %s): "+
					"name a socket the agent's user may use in [containers] sockets, "+
					"or set enabled = false there", runtime, strings.Join(paths, ", "))
			}
		}
		return oneError(errs)
	}
	for _, err := range errs {
		r.Errors = append(r.Errors, report.Problem{Collector: c.Name(), Message: err.Error()})
	}
	return nil
}

// oneError makes one error of several, on one line: it becomes one line on the dashboard.
func oneError(errs []error) error {
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	}
	said := make([]string, len(errs))
	for i, err := range errs {
		said[i] = err.Error()
	}
	return errors.New(strings.Join(said, "; "))
}

// locate checks that path is a socket and says where it really is.
func locate(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("looking for the container runtime's socket: %w", err)
	}
	if info.Mode()&fs.ModeSocket == 0 {
		return "", fmt.Errorf("looking for the container runtime's socket: %s is not a socket", path)
	}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real, nil
	}
	return path, nil
}

// container is one report entry and the ID that tells two sockets of one runtime apart.
type container struct {
	report.Container
	id string
}

// inspectAll reports the containers behind one socket. It returns what it could read together
// with an error for what it could not, so one broken container does not hide the others.
func inspectAll(ctx context.Context, socket string) ([]container, error) {
	ctx, cancel := context.WithTimeout(ctx, socketTimeout)
	defer cancel()
	api := dial(socket)
	defer api.close()

	runtime, err := api.ping(ctx)
	if err != nil {
		return nil, err
	}
	listed, err := api.containers(ctx)
	if err != nil {
		return nil, err
	}

	var out []container
	var errs []error
	images := map[string]imageInfo{} // by image ID: many containers share few images
	for _, l := range listed {
		// "restarting" is Docker's word for a container between two attempts of its restart
		// policy. It is still in use, so its image still matters.
		if l.State != "running" && l.State != "restarting" {
			continue
		}
		// A pod's infra container runs nothing of its own. Newer Podman gives it no image at
		// all; Debian 13's builds it one.
		if l.Image == "" || infraImage(parseReference(l.Image)) {
			continue
		}
		ct := container{id: l.ID, Container: report.Container{
			Name:       strings.TrimPrefix(firstOf(l.Names), "/"),
			ImageID:    l.ImageID,
			State:      l.State,
			AutoUpdate: l.Labels[autoUpdateLabel],
			Runtime:    runtime.name,
		}}
		configured := l.Image

		// The list has no start time, and after a tag moved to a newer image Docker lists the
		// old image's ID where the name was. Only the container's own record has both.
		detail, err := api.container(ctx, l.ID)
		switch {
		case isNotFound(err):
			continue // removed since the list was made
		case err != nil:
			errs = append(errs, err) // what the list says is still worth reporting
		default:
			if detail.State.Status != "running" && detail.State.Status != "restarting" {
				continue // stopped since the list was made
			}
			ct.State = detail.State.Status
			ct.StartedAt = startTime(detail.State.StartedAt)
			if detail.Name != "" {
				ct.Name = strings.TrimPrefix(detail.Name, "/")
			}
			if detail.Image != "" {
				ct.ImageID = detail.Image
			}
			if detail.Config.Image != "" {
				configured = detail.Config.Image
			}
			if v, ok := detail.Config.Labels[autoUpdateLabel]; ok {
				ct.AutoUpdate = v
			}
		}
		img, known := images[ct.ImageID]
		if !known && strings.TrimPrefix(ct.ImageID, "sha256:") != "" {
			if img, err = api.image(ctx, runtime, ct.ImageID); err != nil {
				errs = append(errs, err)
			}
			images[ct.ImageID] = img
		}

		if imageID(configured, ct.ImageID) {
			// Started from an image ID: the nearest thing to "as configured" is a name the
			// image has. Without one the full ID is all there is to say.
			switch {
			case len(img.RepoTags) > 0:
				configured = img.RepoTags[0]
			case len(img.RepoDigests) > 0:
				configured = img.RepoDigests[0]
			default:
				ct.Image = ct.ImageID
				out = append(out, ct)
				continue
			}
		}
		ref := parseReference(configured)
		if infraImage(ref) {
			continue // not seen in the list, where Docker shows an ID once the image's tag has moved
		}
		ct.Image = ref.String()
		ct.Digest, ct.Digests = pulledAs(ref, img)
		out = append(out, ct)
	}
	return out, errors.Join(errs...)
}

// pulledAs is the digest the registry had for the image when it was pulled, which is what the
// server compares with what the tag points at today. It is empty when that is not known for
// sure: a wrong digest would report a rebuilt tag for ever. all lists every digest the image
// goes by in the container's repository, so that the server can still tell "the tag points at
// this very image" when one digest cannot be singled out; it is left empty when it would say
// nothing the one digest does not.
func pulledAs(ref reference, img imageInfo) (digest string, all []string) {
	var ours []string // the digests the image goes by in this container's repository
	seen := map[string]bool{}
	for _, rd := range img.RepoDigests {
		if d := parseReference(rd); d.repo == ref.repo && d.digest != "" && !seen[d.digest] {
			seen[d.digest] = true
			ours = append(ours, d.digest)
		}
	}
	switch {
	case ref.digest != "":
		digest = ref.digest // the container names it itself
	case len(ours) == 1:
		digest = ours[0]
	case len(ours) == 2 && (img.Digest == ours[0] || img.Digest == ours[1]):
		// Podman lists two digests for an image that exists for several architectures, in
		// the order of their text: the one of the whole set, which is what the tag points at,
		// and the one of this machine's variant. Its own record of the image keeps the one
		// the image was first pulled as (recomputeDigests in containers/storage, images.go).
		digest = img.Digest
	}
	// More than two: the image was pulled again as part of a newer set that still holds the
	// same variant, and nothing records which set is the current one. The list still tells.
	if len(ours) == 1 && ours[0] == digest {
		return digest, nil
	}
	return digest, ours
}

func firstOf(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// startTime reads the runtime's start time. A container that never started has year 1.
func startTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() <= 1 {
		return time.Time{}
	}
	return t.UTC()
}
