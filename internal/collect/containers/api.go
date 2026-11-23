package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// requestTimeout bounds one call. The runtime is local, so anything slower is stuck.
	requestTimeout = 10 * time.Second
	// maxBody caps what is read of one answer. A list of some hundred containers is well under
	// a megabyte.
	maxBody = 16 << 20
)

// client speaks HTTP to a runtime over its unix socket.
type client struct {
	socket string
	http   *http.Client
}

func dial(socket string) *client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns: 1,
	}
	return &client{socket: socket, http: &http.Client{Transport: transport}}
}

func (c *client) close() { c.http.CloseIdleConnections() }

// engine is which runtime answers on a socket.
type engine struct {
	name   string // "podman" or "docker"
	libpod string // Podman's own API version, empty for Docker
}

// listed is one entry of GET /containers/json.
type listed struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Labels  map[string]string `json:"Labels"`
	Ports   []listedPort      `json:"Ports"`
}

// listedPort is one port of a container in the list: published when PublicPort is set.
type listedPort struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

// inspected is what GET /containers/{id}/json adds to the list.
type inspected struct {
	Name  string `json:"Name"`
	Image string `json:"Image"` // the image's ID
	State struct {
		Status    string `json:"Status"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"` // the reference the container was created with
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"` // "host" when it shares the host's network
	} `json:"HostConfig"`
}

// imageInfo is what the runtime knows about a local image.
type imageInfo struct {
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	Digest      string   `json:"Digest"` // Podman's own API only: the digest the image was pulled as
}

// ping finds out which runtime listens. Podman names its own API's version in a header of
// every answer; Docker has no such header.
func (c *client) ping(ctx context.Context) (engine, error) {
	header, err := c.get(ctx, "/_ping", nil)
	if err != nil {
		return engine{}, fmt.Errorf("asking which container runtime listens on %s: %w", c.socket, err)
	}
	if v := header.Get("Libpod-Api-Version"); v != "" {
		return engine{name: "podman", libpod: v}, nil
	}
	return engine{name: "docker"}, nil
}

// containers lists all containers. Stopped ones come along because Podman refuses the filter
// that would leave them out ("unknown container state: restarting"); the caller drops them.
func (c *client) containers(ctx context.Context) ([]listed, error) {
	var out []listed
	if _, err := c.get(ctx, "/containers/json?all=true", &out); err != nil {
		return nil, fmt.Errorf("listing the containers on %s: %w", c.socket, err)
	}
	return out, nil
}

func (c *client) container(ctx context.Context, id string) (inspected, error) {
	var out inspected
	if _, err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &out); err != nil {
		return inspected{}, fmt.Errorf("inspecting container %s on %s: %w", short(id), c.socket, err)
	}
	return out, nil
}

// image reads an image's names and digests. An image that is gone is not an error: Docker
// keeps a container running after its image was replaced and removed.
func (c *client) image(ctx context.Context, e engine, id string) (imageInfo, error) {
	var out imageInfo
	if e.libpod != "" {
		// Podman's own API says which digest the image was pulled as; Docker's does not.
		// Should that call fail on some version of Podman, Docker's still gives the names.
		_, err := c.get(ctx, "/v"+url.PathEscape(e.libpod)+"/libpod/images/"+url.PathEscape(id)+"/json", &out)
		if err == nil {
			return out, nil
		}
		out = imageInfo{}
	}
	_, err := c.get(ctx, "/images/"+url.PathEscape(id)+"/json", &out)
	switch {
	case isNotFound(err):
		return imageInfo{}, nil
	case err != nil:
		return imageInfo{}, fmt.Errorf("inspecting image %s on %s: %w", short(id), c.socket, err)
	}
	return out, nil
}

// statusError is an answer other than 200.
type statusError struct {
	code    int
	message string
}

func (e *statusError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("the runtime answered %d", e.code)
	}
	return fmt.Sprintf("the runtime answered %d: %s", e.code, e.message)
}

func isNotFound(err error) bool {
	var se *statusError
	return errors.As(err, &se) && se.code == http.StatusNotFound
}

// get makes one call and decodes its JSON answer into "into", unless that is nil.
func (c *client) get(ctx context.Context, path string, into any) (http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	// The host is only there to make a valid URL: the connection goes to the socket.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+path, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		// url.Error repeats the made-up URL; what went wrong is inside it.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("reading the answer: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		// Both runtimes explain an error as {"message": "..."}.
		var problem struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &problem)
		return nil, &statusError{code: res.StatusCode, message: clip(problem.Message, 200)}
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("the answer is larger than %d MiB", maxBody>>20)
	}
	if into != nil {
		if err := json.Unmarshal(body, into); err != nil {
			return nil, fmt.Errorf("reading the answer: %w", err)
		}
	}
	return res.Header, nil
}

// short keeps enough of an ID to find the container or image with.
func short(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// clip keeps a message from the runtime to one short line.
func clip(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	for i := range s {
		if i >= max {
			return s[:i] + "..."
		}
	}
	return s
}
