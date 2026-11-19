package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/version"
)

const (
	sendTimeout = 30 * time.Second // one attempt, from connecting to the last byte of the answer
	firstRetry  = 5 * time.Second
	maxRetry    = 5 * time.Minute
	onceTries   = 3 // "-once" gives up after this many attempts
)

// sender delivers reports to one server.
type sender struct {
	url       string
	tokenFile string
	client    *http.Client
}

func newSender(url, tokenFile string) *sender {
	return &sender{
		url:       url,
		tokenFile: tokenFile,
		client: &http.Client{
			Timeout: sendTimeout,
			// A redirect turns a POST into a GET, and the answer to that GET would read as
			// "delivered". The server's address is to be configured right instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// refused is an answer that sending the same report again will not change: a wrong token, a
// wrong address, a report the server does not accept.
type refused struct{ msg string }

func (r *refused) Error() string { return r.msg }

// send makes one attempt. The token is read on every attempt, so a new token only needs a
// new file, and it never appears in an error.
func (s *sender) send(ctx context.Context, body []byte) error {
	token, err := readToken(s.tokenFile)
	if err != nil {
		return &refused{err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return &refused{fmt.Sprintf("build the request to %s: %v", s.url, err)}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "upkeep-agent/"+version.Version)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send the report: %w", err) // the error names the URL itself
	}
	defer resp.Body.Close()
	said, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	msg := fmt.Sprintf("send the report to %s: the server answered %s", s.url, resp.Status)
	if loc := resp.Header.Get("Location"); loc != "" {
		msg += " and points to " + loc
	}
	if text := oneLine(string(said)); text != "" {
		msg += ": " + text
	}
	switch code := resp.StatusCode; {
	case code >= 500, code == http.StatusRequestTimeout, code == http.StatusTooEarly, code == http.StatusTooManyRequests:
		return errors.New(msg) // the server's trouble, which may pass
	}
	return &refused{msg}
}

// readToken returns the token in the file. Errors name the file, never its content.
func readToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read the token file: %w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("the token file %s is empty", path)
	}
	// A token goes into a header as it is: more than one line, or anything but printable
	// ASCII, cannot be one.
	for _, c := range token {
		if c <= ' ' || c > '~' {
			return "", fmt.Errorf("the token file %s must hold a single token on one line", path)
		}
	}
	return token, nil
}

// oneLine makes the start of a server's answer fit a log line.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(strings.ToValidUTF8(s, "?")), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// deliver sends body until the server takes it. It stops trying when the server refuses the
// report, when tries attempts were made (0 means no limit), when the next report is due at
// deadline anyway, or when the agent is stopping. Between attempts it waits, twice as long
// each time, so a server that is away is not hammered and one that comes back is found soon.
func (a *agent) deliver(ctx context.Context, body []byte, tries int, deadline time.Time) error {
	wait := firstRetry
	for attempt := 1; ; attempt++ {
		err := a.send(ctx, body)
		if err == nil {
			return nil
		}
		var no *refused
		if errors.As(err, &no) || ctx.Err() != nil {
			return err
		}
		if tries > 0 && attempt >= tries {
			return fmt.Errorf("%w (gave up after %d attempts)", err, attempt)
		}
		pause := a.jitter(wait)
		if !deadline.IsZero() && a.now().Add(pause).After(deadline) {
			return fmt.Errorf("%w (gave up: the next report is due)", err)
		}
		a.logf("report not delivered, trying again in %s: %v", pause.Round(time.Second), err)
		if !a.sleep(ctx, pause) {
			return err
		}
		if wait *= 2; wait > maxRetry {
			wait = maxRetry
		}
	}
}
