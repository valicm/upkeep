// Package registry asks container registries what exists for an image in use.
//
// It speaks the OCI distribution API without credentials, the way an anonymous "pull" starts:
// Docker Hub, ghcr.io, lscr.io and quay.io all answer it for public images. It only ever
// reads: one HEAD for what the tag points at now, and the list of the repository's tags.
package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/valicm/upkeep/internal/model"
)

const (
	defaultTimeout = 15 * time.Second
	defaultMaxTags = 10000
	// defaultPageSize is the most Docker Hub and ghcr.io give in one page; quay.io gives 100
	// whatever is asked.
	defaultPageSize = 1000
	// fallbackPageSize is asked for when a registry refuses the bigger page.
	fallbackPageSize = 100
	// maxPages stops a registry that keeps sending small or empty pages.
	maxPages = 100
)

// Options configures a Client. The zero value works.
type Options struct {
	HTTP    *http.Client     // nil: a client of its own that only follows redirects to https
	Now     func() time.Time // nil: time.Now
	Timeout time.Duration    // for each request to a registry; 0: 15 seconds
	MaxTags int              // how many tags of one repository are read; 0: 10000
}

// Client talks to registries. It is safe for concurrent use.
type Client struct {
	http     *http.Client
	now      func() time.Time
	timeout  time.Duration
	maxTags  int
	pageSize int

	mu         sync.Mutex
	challenges map[string]challenge // by API host: where that registry sends clients for a token
	tokens     map[string]token     // by API host and repository
}

// New returns a Client.
func New(opts Options) *Client {
	c := &Client{
		http:       opts.HTTP,
		now:        opts.Now,
		timeout:    opts.Timeout,
		maxTags:    opts.MaxTags,
		pageSize:   defaultPageSize,
		challenges: map[string]challenge{},
		tokens:     map[string]token{},
	}
	if c.http == nil {
		c.http = &http.Client{CheckRedirect: httpsOnly}
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.timeout <= 0 {
		c.timeout = defaultTimeout
	}
	if c.maxTags <= 0 {
		c.maxTags = defaultMaxTags
	}
	return c
}

// httpsOnly keeps a redirect from moving a request, and the token it carries, to plain HTTP.
func httpsOnly(req *http.Request, via []*http.Request) error {
	switch {
	case len(via) >= 5:
		return errors.New("too many redirects")
	case req.URL.Scheme != "https":
		return errors.New("redirect to a URL that is not https")
	}
	return nil
}

// Check asks the registry of image (a reference as a container runtime prints it) what its tag
// points at now and which newer version tags exist. It never returns an error: a failure is in
// the result's Error field, so that it can be stored and shown.
//
// An image no registry can be asked about (one built locally under "localhost/", or one pinned
// by digest with no tag) is not a failure: the result then says nothing and has no Error. When
// Error is set, the fields that are filled are still what the registry said just now. Note is
// set when the answer is good but may be incomplete.
func (c *Client) Check(ctx context.Context, image string) model.ImageCheck {
	out := model.ImageCheck{Image: image, CheckedAt: c.now()}
	ref, err := parseReference(image)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Tag = ref.tag
	if ref.local() || ref.tag == "" {
		return out
	}

	var problems []string
	digest, err := c.tagDigest(ctx, ref)
	switch {
	case err == nil:
		out.TagDigest = digest
	case errors.Is(err, errNoSuchTag):
		// The tag was deleted. The repository is still there, so newer tags are worth a look.
		problems = append(problems, fmt.Sprintf("%s has no tag %s (any more)", ref.name(), ref.tag))
	default:
		// The registry did not answer or does not show this repository: do not ask twice.
		out.Error = fmt.Sprintf("asking what %s:%s points at: %s", ref.name(), ref.tag, c.reason(err))
		return out
	}

	// A tag that is not a version ("latest", "stable") has nothing to be compared with.
	if _, isVersion := parseTag(ref.tag); isVersion {
		tags, note, err := c.listTags(ctx, ref)
		if err != nil {
			problems = append(problems, fmt.Sprintf("listing the tags of %s: %s", ref.name(), c.reason(err)))
		}
		// Not every tag was read: what was found is real, only the newest may be missing.
		// That is a remark, not a failure, and for a repository with more tags than the
		// limit it is there for good.
		out.Note = note
		out.NewerPatch, out.NewerMinor, out.NewerMajor = newerTags(ref.tag, tags)
	}
	out.Error = strings.Join(problems, "; ")
	return out
}
