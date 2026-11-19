package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBaseURL(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr string
	}{
		{in: "https://10.0.0.1", want: "https://10.0.0.1"},
		{in: " https://fw.example.net:8443/ ", want: "https://fw.example.net:8443"},
		{in: "http://supervisor/core", want: "http://supervisor/core"},
		{in: "http://supervisor/core/", want: "http://supervisor/core"},
		{in: "https://[fd00::1]:8443", want: "https://[fd00::1]:8443"},
		{in: "", wantErr: `url must start with "https://" or "http://"`},
		{in: "fw.example.net", wantErr: `url must start with "https://" or "http://"`},
		{in: "ftp://fw.example.net", wantErr: `url must start with "https://" or "http://"`},
		{in: "https://", wantErr: "url has no host"},
		{in: "https://user:hunter2@fw.example.net", wantErr: "url must not contain a user or password"},
		// A secret with a slash in it does not parse as a user, and still must not stay in the URL.
		{in: "https://ab/cd:hunter2@fw.example.net", wantErr: "url must not contain a user or password"},
		{in: "https://fw.example.net/?key=hunter2", wantErr: "url must not have a query or fragment"},
		{in: "https://fw.example.net/#hunter2", wantErr: "url must not have a query or fragment"},
		{in: "https://fw.example.net/%zzhunter2", wantErr: "url is not a valid URL"},
	}
	for _, tt := range tests {
		u, err := BaseURL(tt.in)
		switch {
		case tt.wantErr == "" && err != nil:
			t.Errorf("BaseURL(%q): %v", tt.in, err)
		case tt.wantErr == "":
			if u.String() != tt.want {
				t.Errorf("BaseURL(%q) = %s, want %s", tt.in, u, tt.want)
			}
			if got, want := u.JoinPath("api", "states").String(), tt.want+"/api/states"; got != want {
				t.Errorf("BaseURL(%q) with a path = %s, want %s", tt.in, got, want)
			}
		case err == nil || err.Error() != tt.wantErr && !strings.HasPrefix(err.Error(), tt.wantErr):
			t.Errorf("BaseURL(%q): error %v, want %q", tt.in, err, tt.wantErr)
		case strings.Contains(err.Error(), "hunter2"):
			t.Errorf("BaseURL(%q): the error repeats the secret: %v", tt.in, err)
		}
	}
}

func TestReadSecret(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		content string // "-" for no file
		want    string
		wantErr string
	}{
		{name: "one line", content: "s3cret-token\n", want: "s3cret-token"},
		{name: "no line end", content: "s3cret-token", want: "s3cret-token"},
		{name: "spaces around", content: "  s3cret-token \r\n\n", want: "s3cret-token"},
		{name: "empty", content: "\n", wantErr: "is empty"},
		{name: "two lines", content: "s3cret-token\nand-more\n", wantErr: "has more than one line"},
		{name: "missing", content: "-", wantErr: "no such file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "-"))
			if tt.content != "-" {
				if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := ReadSecret(path)
			switch {
			case tt.wantErr == "":
				if err != nil || got != tt.want {
					t.Errorf("got %q, %v; want %q", got, err, tt.want)
				}
			case err == nil || !strings.Contains(err.Error(), tt.wantErr) || !strings.Contains(err.Error(), path):
				t.Errorf("error = %v, want %q with the path", err, tt.wantErr)
			case strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "and-more"):
				t.Errorf("the error shows what is in the file: %v", err)
			}
		})
	}
}

func TestDuration(t *testing.T) {
	tests := []struct {
		value   string
		want    time.Duration
		wantErr string
	}{
		{value: "", want: 15 * time.Second},
		{value: " 30s ", want: 30 * time.Second},
		{value: "12h", want: 12 * time.Hour},
		{value: "0", want: 0},
		{value: "15", wantErr: `timeout: "15" is not a duration like "15s" or "12h"`},
		{value: "two minutes", wantErr: `timeout: "two minutes" is not a duration`},
		{value: "-5s", wantErr: "timeout must not be negative"},
	}
	for _, tt := range tests {
		got, err := Duration("timeout", tt.value, 15*time.Second)
		switch {
		case tt.wantErr == "":
			if err != nil || got != tt.want {
				t.Errorf("Duration(%q) = %v, %v; want %v", tt.value, got, err, tt.want)
			}
		case err == nil || !strings.Contains(err.Error(), tt.wantErr):
			t.Errorf("Duration(%q): error %v, want %q", tt.value, err, tt.wantErr)
		}
	}
}

func TestDo(t *testing.T) {
	const body = `{"status":"ok"}`
	tests := []struct {
		name    string
		handler http.HandlerFunc
		limit   int64
		want    string // "" for success
		is      error
	}{
		{
			name:    "an answer",
			handler: func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) },
			limit:   1 << 10,
		},
		{
			name:    "an answer of exactly the limit",
			handler: func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) },
			limit:   int64(len(body)),
		},
		{
			name:    "an answer one byte over the limit",
			handler: func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body+" ") },
			limit:   int64(len(body)),
			want:    "reading the answer: the answer is larger than expected", is: ErrTooLarge,
		},
		{
			name: "another status",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "the body may say anything: hunter2", http.StatusBadGateway)
			},
			limit: 1 << 10,
			want:  "HTTP 502 Bad Gateway",
		},
		{
			name: "a redirect is an answer, not a place to go",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently)
			},
			limit: 1 << 10,
			want:  "HTTP 301 Moved Permanently",
		},
		{
			name:    "not JSON",
			handler: func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "<html>") },
			limit:   1 << 10,
			want:    "the answer is not the expected JSON",
		},
		{
			name:    "JSON of another shape",
			handler: func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"status":[1,2]}`) },
			limit:   1 << 10,
			want:    "the answer is not the expected JSON",
		},
		{
			name:    "no answer in time",
			handler: func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() },
			limit:   1 << 10,
			want:    "no answer within", is: context.DeadlineExceeded,
		},
	}
	client, err := NewClient(TLS{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elsewhere := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/elsewhere" {
					elsewhere = true
				}
				if r.Header.Get("Authorization") != "Bearer hunter2" {
					t.Error("the request arrived without its header")
				}
				tt.handler(w, r)
			}))
			defer srv.Close()
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api", nil)
			req.Header.Set("Authorization", "Bearer hunter2")
			var got struct {
				Status string `json:"status"`
			}
			err := Do(context.Background(), client, req, 100*time.Millisecond, tt.limit, func(r io.Reader) error {
				if err := json.NewDecoder(r).Decode(&got); err != nil {
					return err
				}
				_, err := io.Copy(io.Discard, r) // to the end, as a reader of a list would
				return err
			})
			switch {
			case tt.want == "":
				if err != nil || got.Status != "ok" {
					t.Errorf("got %+v, %v", got, err)
				}
			case err == nil || !strings.Contains(err.Error(), tt.want):
				t.Errorf("error = %v, want %q", err, tt.want)
			case tt.is != nil && !errors.Is(err, tt.is):
				t.Errorf("error = %v, want errors.Is %v", err, tt.is)
			case strings.Contains(err.Error(), "hunter2"):
				t.Errorf("the error repeats the secret or the body: %v", err)
			}
			if elsewhere {
				t.Error("the redirect was followed, with the credentials")
			}
		})
	}
}

// A parent context that ends first ends the request, whatever the timeout.
func TestDoStopsWithItsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	client, _ := NewClient(TLS{})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	start := time.Now()
	err := Do(ctx, client, req, time.Minute, 1<<10, func(io.Reader) error { return nil })
	if !errors.Is(err, context.Canceled) || time.Since(start) > 10*time.Second {
		t.Errorf("error = %v after %s, want context.Canceled at once", err, time.Since(start))
	}
}

func TestNewClient(t *testing.T) {
	c, err := NewClient(TLS{ServerName: "fw.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	tr := c.Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Error("the client would use a proxy from the environment")
	}
	if tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.ServerName != "fw.example.net" || tr.TLSClientConfig.RootCAs != nil {
		t.Errorf("TLS settings: %+v", tr.TLSClientConfig)
	}
	if c, _ := NewClient(TLS{SkipVerify: true}); !c.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Error("SkipVerify is not taken over")
	}
	if _, err := NewClient(TLS{CAFile: filepath.Join(t.TempDir(), "gone.pem")}); err == nil || !strings.Contains(err.Error(), "reading the certificates to trust") {
		t.Errorf("a missing CA file: %v", err)
	}
}
