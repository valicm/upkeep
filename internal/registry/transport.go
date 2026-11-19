package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	userAgent = "upkeep (container image update check)"

	// manifestAccept names every manifest format. Without the index types ghcr.io answers 404
	// for a multi-platform tag ("OCI index found, but Accept header does not support OCI
	// indexes"), and a registry may as well answer with one platform's manifest, which is not
	// what the tag points at.
	manifestAccept = "application/vnd.oci.image.index.v1+json, " +
		"application/vnd.docker.distribution.manifest.list.v2+json, " +
		"application/vnd.oci.image.manifest.v1+json, " +
		"application/vnd.docker.distribution.manifest.v2+json"

	maxTokenBody = 64 << 10 // Docker Hub's token answer is under 6 KiB
	maxTagsBody  = 4 << 20  // 1000 tags of the longest allowed name are under 200 KiB
	maxErrorBody = 4 << 10  // enough for the error code

	// minTokenLife is what a token lives when the service does not say; the token
	// specification (distribution/spec/auth/token.md) sets it. tokenMargin is taken off so
	// that a token does not expire on its way to the registry.
	minTokenLife = 60 * time.Second
	tokenMargin  = 10 * time.Second
	maxTokens    = 256
)

var (
	errNoSuchTag = errors.New("no such tag")
	// challengeParamRE reads realm="...", service="..." out of a WWW-Authenticate header.
	challengeParamRE = regexp.MustCompile(`([a-zA-Z_]+)="([^"]*)"`)
	errorCodeRE      = regexp.MustCompile(`^[A-Z][A-Z_]{1,39}$`)
)

// challenge is where a registry sends a client that has no token.
type challenge struct{ realm, service string }

// token is a bearer token for pulling from one repository.
type token struct {
	value   string
	expires time.Time
}

// response is an answer that was read completely.
type response struct {
	status int
	header http.Header
	body   []byte
}

// send makes one request with the per-request timeout and reads at most limit bytes of the
// answer. bearer is never part of an error.
func (c *Client) send(ctx context.Context, method, rawurl, accept, bearer string, limit int64) (*response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	res := &response{status: resp.StatusCode, header: resp.Header}
	if resp.StatusCode != http.StatusOK {
		// Only the error code is of interest; the rest of an error page may be cut off.
		res.body, _ = io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return res, nil
	}
	res.body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	switch {
	case err != nil:
		return nil, err
	case int64(len(res.body)) > limit:
		return nil, fmt.Errorf("the answer is larger than %d bytes", limit)
	}
	return res, nil
}

// call sends a request about ref's repository to its registry, getting an anonymous token
// first when the registry wants one: it answers 401 and names a token service, the service
// gives a token for pulling from this one repository, and the request is sent again with it.
func (c *Client) call(ctx context.Context, ref reference, method, rawurl, accept string, limit int64) (*response, error) {
	host, key := ref.apiHost(), ref.apiHost()+"/"+ref.repo
	bearer := c.cachedToken(key)
	var askedOf challenge // the token service a token was just fetched from, if any
	if bearer == "" {
		// This registry asked for a token before: save the round trip that ends in 401.
		if ch, known := c.challengeOf(host); known {
			var err error
			if bearer, err = c.fetchToken(ctx, ch, host, ref.repo); err != nil {
				return nil, err
			}
			askedOf = ch
		}
	}
	res, err := c.send(ctx, method, rawurl, accept, bearer, limit)
	if err != nil || res.status != http.StatusUnauthorized {
		return res, err
	}
	ch, ok := parseChallenge(res.header.Values("WWW-Authenticate"))
	if !ok || ch == askedOf {
		// No token service is named, or a token it just issued is refused: the repository is
		// not for the public (Docker Hub says so for one that does not exist too). Asking
		// again does not help.
		return res, nil
	}
	c.mu.Lock()
	c.challenges[host] = ch
	if t, cached := c.tokens[key]; cached && t.value == bearer {
		delete(c.tokens, key) // the registry no longer takes it
	}
	c.mu.Unlock()
	// Another check of the same repository may have got a token in the meantime.
	if bearer = c.cachedToken(key); bearer == "" {
		if bearer, err = c.fetchToken(ctx, ch, host, ref.repo); err != nil {
			return nil, err
		}
	}
	return c.send(ctx, method, rawurl, accept, bearer, limit)
}

func (c *Client) cachedToken(key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tokens[key]; ok && c.now().Before(t.expires) {
		return t.value
	}
	return ""
}

func (c *Client) challengeOf(host string) (challenge, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.challenges[host]
	return ch, ok
}

// parseChallenge reads a header like the one Docker Hub sends:
//
//	Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:gitea/gitea:pull"
func parseChallenge(headers []string) (challenge, bool) {
	for _, h := range headers {
		scheme, params, _ := strings.Cut(strings.TrimSpace(h), " ")
		if !strings.EqualFold(scheme, "Bearer") {
			continue
		}
		var ch challenge
		for _, m := range challengeParamRE.FindAllStringSubmatch(params, -1) {
			switch strings.ToLower(m[1]) {
			case "realm":
				ch.realm = m[2]
			case "service":
				ch.service = m[2]
			}
		}
		if ch.realm != "" {
			return ch, true
		}
	}
	return challenge{}, false
}

// fetchToken asks a token service for an anonymous token that may pull from one repository,
// and keeps it until it expires. The scope is built here and not taken from the registry, so
// the token is never good for more than this.
func (c *Client) fetchToken(ctx context.Context, ch challenge, host, repo string) (string, error) {
	u, err := url.Parse(ch.realm)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		c.forgetChallenge(host)
		return "", fmt.Errorf("%s names a token service that is not an https address", host)
	}
	q := u.Query()
	if ch.service != "" {
		q.Set("service", ch.service)
	}
	q.Set("scope", "repository:"+repo+":pull")
	u.RawQuery = q.Encode()
	res, err := c.send(ctx, http.MethodGet, u.String(), "application/json", "", maxTokenBody)
	if err != nil {
		c.forgetChallenge(host)
		return "", fmt.Errorf("getting a token from %s: %s", u.Host, c.reason(err))
	}
	if res.status != http.StatusOK {
		c.forgetChallenge(host)
		return "", fmt.Errorf("getting a token from %s: %s", u.Host, statusText(res))
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	// The answer holds a secret, so no part of it goes into an error.
	if err := json.Unmarshal(res.body, &body); err != nil {
		return "", fmt.Errorf("getting a token from %s: the answer is not JSON", u.Host)
	}
	value := body.Token
	if value == "" {
		value = body.AccessToken
	}
	if !usableToken(value) {
		return "", fmt.Errorf("getting a token from %s: the answer has no usable token", u.Host)
	}
	life := time.Duration(min(body.ExpiresIn, 24*3600)) * time.Second
	if life < minTokenLife {
		life = minTokenLife
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.tokens) >= maxTokens {
		for k, t := range c.tokens {
			if !now.Before(t.expires) {
				delete(c.tokens, k)
			}
		}
		if len(c.tokens) >= maxTokens {
			clear(c.tokens)
		}
	}
	c.tokens[host+"/"+repo] = token{value: value, expires: now.Add(life - tokenMargin)}
	return value, nil
}

// usableToken reports whether a token can go into a header as it is.
func usableToken(s string) bool {
	if s == "" || len(s) > 16<<10 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// forgetChallenge makes the next request ask the registry again where its token service is.
func (c *Client) forgetChallenge(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.challenges, host)
}

// tagDigest asks what ref's tag points at. HEAD is enough, and Docker Hub does not count it
// against the pull limit as it does a GET of the manifest.
func (c *Client) tagDigest(ctx context.Context, ref reference) (string, error) {
	u := url.URL{Scheme: "https", Host: ref.apiHost(), Path: "/v2/" + ref.repo + "/manifests/" + ref.tag}
	res, err := c.call(ctx, ref, http.MethodHead, u.String(), manifestAccept, 0)
	switch {
	case err != nil:
		return "", err
	case res.status == http.StatusNotFound:
		return "", errNoSuchTag
	case res.status != http.StatusOK:
		return "", errors.New(statusText(res))
	}
	digest := res.header.Get("Docker-Content-Digest")
	if !digestRE.MatchString(digest) {
		return "", errors.New("the registry did not name a digest")
	}
	return digest, nil
}

// listTags reads the tags of ref's repository, page by page, up to the client's limit. note
// is set when not every tag was read: the tags returned are then still real, but the newest
// may be missing.
func (c *Client) listTags(ctx context.Context, ref reference) (tags []string, note string, err error) {
	size := min(c.pageSize, c.maxTags)
	first := func() *url.URL {
		return &url.URL{Scheme: "https", Host: ref.apiHost(), Path: "/v2/" + ref.repo + "/tags/list", RawQuery: "n=" + strconv.Itoa(size)}
	}
	page := first()
	cut := fmt.Sprintf("only the first %d tags of %s were read, newer ones may be missing", c.maxTags, ref.name())
	for pages := 1; ; pages++ {
		res, err := c.call(ctx, ref, http.MethodGet, page.String(), "application/json", maxTagsBody)
		if err == nil && res.status == http.StatusBadRequest && pages == 1 && size > fallbackPageSize {
			// Some registries refuse a page size above their own limit instead of lowering it.
			size = fallbackPageSize
			page = first()
			res, err = c.call(ctx, ref, http.MethodGet, page.String(), "application/json", maxTagsBody)
		}
		switch {
		case err != nil:
			return nil, "", err
		case res.status != http.StatusOK:
			return nil, "", errors.New(statusText(res))
		}
		var body struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(res.body, &body); err != nil {
			return nil, "", errors.New("the answer is not a list of tags")
		}
		for _, t := range body.Tags {
			if tagRE.MatchString(t) {
				tags = append(tags, t)
			}
		}
		next := nextLink(res.header, page)
		switch {
		case len(tags) > c.maxTags:
			return tags[:c.maxTags], cut, nil
		case next == nil:
			return tags, "", nil
		case len(tags) == c.maxTags:
			return tags, cut, nil
		case pages == maxPages:
			return tags, fmt.Sprintf("only the first %d pages of the tags of %s were read, newer ones may be missing", maxPages, ref.name()), nil
		case next.Scheme != page.Scheme || next.Host != page.Host || next.String() == page.String():
			// Following it would send the token elsewhere, or go round in a circle.
			return tags, fmt.Sprintf("%s did not say properly where its tag list goes on, newer tags may be missing", ref.apiHost()), nil
		}
		page = next
	}
}

// nextLink finds the next page in a Link header (RFC 8288), as registries send it:
//
//	</v2/gitea/gitea/tags/list?last=1-linux-arm64-rootless&n=5>; rel="next"
func nextLink(h http.Header, page *url.URL) *url.URL {
	for _, v := range h.Values("Link") {
		for {
			open := strings.IndexByte(v, '<')
			if open < 0 {
				break
			}
			end := strings.IndexByte(v[open:], '>')
			if end < 0 {
				break
			}
			target, params := v[open+1:open+end], v[open+end+1:]
			if comma := strings.IndexByte(params, ','); comma >= 0 {
				params, v = params[:comma], params[comma+1:]
			} else {
				v = ""
			}
			if !relNext(params) {
				continue
			}
			if u, err := page.Parse(target); err == nil {
				return u
			}
		}
	}
	return nil
}

// relNext reports whether the parameters of a link say rel="next".
func relNext(params string) bool {
	for _, p := range strings.Split(params, ";") {
		name, value, _ := strings.Cut(strings.TrimSpace(p), "=")
		if !strings.EqualFold(strings.TrimSpace(name), "rel") {
			continue
		}
		for _, rel := range strings.Fields(strings.Trim(strings.TrimSpace(value), `"`)) {
			if strings.EqualFold(rel, "next") {
				return true
			}
		}
	}
	return false
}

// statusText says what an answer that is not 200 means.
func statusText(res *response) string {
	var what string
	switch res.status {
	case http.StatusUnauthorized, http.StatusForbidden:
		what = "not found, or not public"
	case http.StatusNotFound:
		what = "not found"
	case http.StatusTooManyRequests:
		what = "too many requests, the registry asks to slow down"
	default:
		what = "unexpected answer"
	}
	var body struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	// The code is the registry's own word for it ("NAME_UNKNOWN", "TOOMANYREQUESTS"). Its free
	// text is left out: it is not ours to put on a dashboard.
	if json.Unmarshal(res.body, &body) == nil && len(body.Errors) > 0 && errorCodeRE.MatchString(body.Errors[0].Code) {
		return fmt.Sprintf("%s (HTTP %d %s)", what, res.status, body.Errors[0].Code)
	}
	return fmt.Sprintf("%s (HTTP %d)", what, res.status)
}

// reason turns an error of a request into a short text without the URL, which the message
// around it already names.
func (c *Client) reason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("no answer within %s", c.timeout)
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	return err.Error()
}
