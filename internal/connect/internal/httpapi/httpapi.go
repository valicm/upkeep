// Package httpapi holds what the appliance sources share: an HTTP client that is careful about
// where a secret can end up, reading that secret from a file, and bounded requests.
package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// TLS says how to check the appliance's certificate. The zero value checks it against the
// system's certificate authorities, which is what a source does unless told otherwise.
type TLS struct {
	CAFile     string // PEM certificates to trust instead of the system's
	ServerName string // name to expect in the certificate, when the URL has an address
	SkipVerify bool   // accept any certificate
}

// NewClient returns a client for one appliance. It never follows a redirect and never uses a
// proxy from the environment: both would hand the appliance's credentials to another host.
func NewClient(t TLS) (*http.Client, error) {
	conf := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         t.ServerName,
		InsecureSkipVerify: t.SkipVerify,
	}
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading the certificates to trust: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("reading the certificates to trust: no PEM certificate in %s", t.CAFile)
		}
		conf.RootCAs = pool
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:             nil,
			TLSClientConfig:   conf,
			DisableKeepAlives: true, // polled every few minutes at most: an idle connection is of no use
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// BaseURL parses the address of an appliance from the configuration. Credentials in the URL are
// refused because a URL is logged and shown in errors.
func BaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	// Any "@" is refused, not only a parsed user: a key with a slash in it turns into host and
	// path, and would be printed with every failed request.
	if strings.Contains(raw, "@") {
		return nil, errors.New("url must not contain a user or password: put secrets in a file")
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Parse quotes its input in the error.
		return nil, errors.New("url is not a valid URL")
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, errors.New(`url must start with "https://" or "http://"`)
	case u.Host == "":
		return nil, errors.New("url has no host")
	case u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("url must not have a query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// ReadSecret returns the content of a secret file without the surrounding white space. The
// error names the file and never what is in it.
func ReadSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err // an *os.PathError: it has the path and the reason, nothing else
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	if strings.ContainsAny(s, "\r\n") {
		return "", fmt.Errorf("%s has more than one line", path)
	}
	return s, nil
}

// Duration parses a setting such as "15s" or "12h". An empty setting gives def.
func Duration(setting, value string, def time.Duration) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return def, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf(`%s: %q is not a duration like "15s" or "12h"`, setting, value)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s must not be negative", setting)
	}
	return d, nil
}

// StatusError is an answer with a status the caller did not ask for. The body is left out on
// purpose: nobody checked what is in it.
type StatusError struct{ Code int }

func (e *StatusError) Error() string {
	return fmt.Sprintf("HTTP %d %s", e.Code, http.StatusText(e.Code))
}

// ErrTooLarge is returned by the reader given to Do's function once the limit is passed.
var ErrTooLarge = errors.New("the answer is larger than expected")

// Do sends one request and gives the body of a 200 answer to read. The timeout covers the whole
// exchange, reading included, and read never gets more than limit bytes. An error of read comes
// back saying whether the answer was not JSON or did not arrive.
func Do(ctx context.Context, c *http.Client, req *http.Request, timeout time.Duration, limit int64, read func(io.Reader) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := c.Do(req.WithContext(ctx))
	if err != nil {
		return late(ctx, "no answer", timeout, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &StatusError{Code: resp.StatusCode}
	}
	err = read(&capped{r: resp.Body, left: limit})
	var syntax *json.SyntaxError
	var kind *json.UnmarshalTypeError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &syntax), errors.As(err, &kind):
		// A login page or another product at this address, most likely.
		return fmt.Errorf("the answer is not the expected JSON: %w", err)
	}
	return late(ctx, "the answer was not complete", timeout, fmt.Errorf("reading the answer: %w", err))
}

// late says in plain words that the appliance took too long, when that is what went wrong:
// "context deadline exceeded" alone does not tell an owner which limit was hit.
func late(ctx context.Context, what string, timeout time.Duration, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) && errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s within %s: %w", what, timeout, err)
	}
	return err
}

// capped fails loudly at the limit: a silently cut answer would look like broken JSON.
type capped struct {
	r    io.Reader
	left int64
}

func (c *capped) Read(p []byte) (int, error) {
	if c.left <= 0 {
		// An answer of exactly the limit is fine: only one more byte makes it too large.
		var one [1]byte
		if n, err := c.r.Read(one[:]); n == 0 {
			return 0, err
		}
		return 0, ErrTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}
