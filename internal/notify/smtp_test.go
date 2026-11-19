package notify

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// What the fake relay answers. Every line was said by a real Mailpit and is in
// testdata/mailpit-plain.txt or testdata/mailpit-starttls.txt (TestRelaySpeaksLikeMailpit
// holds the fake to that), except the refused recipient: Mailpit accepts everybody, so that
// one is the reply Postfix documents for an unknown user.
const (
	sayGreeting   = "220 relay Mailpit ESMTP Service ready"
	sayOK         = "250 2.1.0 Ok"
	sayRcptOK     = "250 2.1.5 Ok"
	sayData       = "354 Start mail input; end with <CR><LF>.<CR><LF>"
	sayQueued     = "250 2.0.0 Ok: queued as 3o8j55ULHTsniP2Z2QJfYr"
	sayBye        = "221 2.0.0 relay Mailpit ESMTP Service closing transmission channel"
	sayNotHere    = "502 5.5.1 Command not implemented"
	sayUnknown    = "500 5.5.2 Syntax error, command unrecognized"
	sayNeedTLS    = "530 5.7.0 Must issue a STARTTLS command first"
	sayNeedLogin  = "530 5.7.0 Authentication required"
	sayTLSReady   = "220 2.0.0 Ready to start TLS"
	sayLoginOK    = "235 2.7.0 Authentication successful"
	sayLoginBad   = "535 5.7.8 Authentication credentials invalid"
	sayRcptReject = "550 5.1.1 <nobody@example.net>: Recipient address rejected: User unknown in local recipient table"
)

func TestRelaySpeaksLikeMailpit(t *testing.T) {
	var real string
	for _, name := range []string{"mailpit-plain.txt", "mailpit-starttls.txt"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		real += string(b)
	}
	for _, line := range []string{sayGreeting, sayOK, sayRcptOK, sayData, sayQueued, sayBye, sayNotHere, sayUnknown,
		sayNeedTLS, sayNeedLogin, sayTLSReady, sayLoginOK, sayLoginBad,
		"250-relay greets workstation.example", "250-SIZE 52428800", "250-STARTTLS", "250-AUTH LOGIN PLAIN",
		"250-ENHANCEDSTATUSCODES", "250-8BITMIME", "250 SMTPUTF8"} {
		if !strings.Contains(real, "S: "+line+"\n") {
			t.Errorf("the fake relay says %q, the recorded Mailpit never did", line)
		}
	}
}

// relay is an SMTP server in the test's own process, behaving like the Mailpit it was
// recorded from.
type relay struct {
	ln       net.Listener
	tls      *tls.Config // set: STARTTLS is offered
	needTLS  bool        // nothing is accepted before STARTTLS
	user     string      // set: a login is needed, with this user
	password string
	mute     bool // accepts the connection and never says a word

	mu       sync.Mutex
	commands []string // every command line received, logins as "AUTH PLAIN user password"
	mails    []mailed
}

type mailed struct {
	from    string
	to      []string
	data    []byte // as it came over the wire, with its CRLFs
	secured bool
	user    string
}

func startRelay(t *testing.T, r *relay) *relay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.ln = ln
	var conns sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Go(func() { r.serve(conn) })
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
		conns.Wait()
	})
	return r
}

func (r *relay) addr() string { return r.ln.Addr().String() }

func (r *relay) delivered() []mailed {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]mailed(nil), r.mails...)
}

func (r *relay) saw(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.commands {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (r *relay) serve(conn net.Conn) {
	defer func() { conn.Close() }()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if r.mute {
		io.Copy(io.Discard, conn) // until the client gives up
		return
	}
	in := bufio.NewReader(conn)
	say := func(lines ...string) { conn.Write([]byte(strings.Join(lines, "\r\n") + "\r\n")) }
	var mailFrom, user string
	var rcpt []string
	secured, loggedIn := false, false
	say(sayGreeting)
	for {
		raw, err := in.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(raw, "\r\n")
		verb, arg, _ := strings.Cut(cmd, " ")
		verb = strings.ToUpper(verb)
		if verb == "AUTH" {
			// Kept readable, so a test can say which password went over the wire.
			if mech, b64, ok := strings.Cut(arg, " "); ok && mech == "PLAIN" {
				if plain, err := base64.StdEncoding.DecodeString(b64); err == nil {
					cmd = "AUTH PLAIN " + strings.Join(strings.Split(string(plain), "\x00")[1:], " ")
				}
			}
		}
		r.mu.Lock()
		r.commands = append(r.commands, cmd)
		r.mu.Unlock()

		switch {
		case verb == "EHLO":
			lines := []string{"250-relay greets " + arg, "250-SIZE 52428800"}
			if r.tls != nil && !secured {
				lines = append(lines, "250-STARTTLS")
			}
			if r.user != "" {
				lines = append(lines, "250-AUTH LOGIN PLAIN")
			}
			say(append(lines, "250-ENHANCEDSTATUSCODES", "250-8BITMIME", "250 SMTPUTF8")...)
		case verb == "QUIT":
			say(sayBye)
			return
		case verb == "STARTTLS" && r.tls != nil && !secured:
			say(sayTLSReady)
			tc := tls.Server(conn, r.tls)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, in, secured = tc, bufio.NewReader(tc), true
		case verb == "STARTTLS":
			say(sayNotHere)
		case r.needTLS && !secured:
			say(sayNeedTLS)
		case verb == "AUTH" && r.user == "":
			say(sayNotHere)
		case verb == "AUTH":
			if cmd == "AUTH PLAIN "+r.user+" "+r.password {
				loggedIn, user = true, r.user
				say(sayLoginOK)
			} else {
				say(sayLoginBad)
			}
		case r.user != "" && !loggedIn:
			say(sayNeedLogin)
		case verb == "MAIL":
			mailFrom, rcpt = address(arg), nil
			say(sayOK)
		case verb == "RCPT":
			if address(arg) == "nobody@example.net" {
				say(sayRcptReject)
				continue
			}
			rcpt = append(rcpt, address(arg))
			say(sayRcptOK)
		case verb == "DATA":
			say(sayData)
			var data bytes.Buffer
			for {
				line, err := in.ReadBytes('\n')
				if err != nil {
					return
				}
				if string(line) == ".\r\n" {
					break
				}
				data.Write(bytes.TrimPrefix(line, []byte("."))) // undo the dot-stuffing
			}
			r.mu.Lock()
			r.mails = append(r.mails, mailed{from: mailFrom, to: rcpt, data: data.Bytes(), secured: secured, user: user})
			r.mu.Unlock()
			say(sayQueued)
		default:
			say(sayUnknown)
		}
	}
}

// address takes "FROM:<a@b> BODY=8BITMIME" and returns "a@b".
func address(arg string) string {
	_, rest, _ := strings.Cut(arg, "<")
	addr, _, _ := strings.Cut(rest, ">")
	return addr
}

// certificate makes a key pair for 127.0.0.1 and writes the certificate where ca_file can
// point at it, the way a homelab's private CA would be given.
func certificate(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "relay-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, path
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const (
	testSubject = "upkeep: 1 critical, 2 warnings – žurno"
	testText    = "1 critical on 1 system.\n\nserver\n  crit  backup restic-backup failed\n.\n.. two dots start this line\n" +
		"a long line: " + "docker.io/library/mariadb:11.4.13, " + "docker.io/photoprism/photoprism:251130, lscr.io/linuxserver/unifi-network-application:10.0.162-ls114\n" +
		"From the dashboard = čćžšđ\n"
	testHTML = "<!DOCTYPE html>\n<html><body><p>1 critical on 1 system.</p>\n<p style=\"color:#b3261e\">backup restic-backup failed – žurno</p></body></html>\n"
	password = "correct horse battery"
)

func TestSend(t *testing.T) {
	tlsConfig, caFile := certificate(t)
	passwordFile := writeFile(t, password+"\n") // as an editor leaves it
	wrongPasswordFile := writeFile(t, "not the password\n")

	tests := []struct {
		name  string
		relay *relay          // nil is a relay like the homelab's: no TLS, no login
		cfg   func(c *Config) // changes to a plain configuration pointing at the relay
		// What must come of it.
		wantErr  []string // parts of the error; none means the mail must arrive
		secured  bool
		user     string
		neverSaw []string // commands the relay must not have received
	}{
		{
			name:     "a relay on the LAN: no TLS, no login",
			neverSaw: []string{"STARTTLS", "AUTH"},
		},
		{
			name:     "STARTTLS on offer is left alone when not asked for",
			relay:    &relay{tls: tlsConfig},
			neverSaw: []string{"STARTTLS", "AUTH"},
		},
		{
			name:    "STARTTLS when asked for",
			relay:   &relay{tls: tlsConfig, needTLS: true},
			cfg:     func(c *Config) { c.StartTLS, c.CAFile = true, caFile },
			secured: true,
		},
		{
			name:    "STARTTLS and a login",
			relay:   &relay{tls: tlsConfig, needTLS: true, user: "upkeep", password: password},
			cfg:     func(c *Config) { c.StartTLS, c.CAFile, c.User, c.PasswordFile = true, caFile, "upkeep", passwordFile },
			secured: true, user: "upkeep",
		},
		{
			name:  "a wrong password is refused and is not in the error",
			relay: &relay{tls: tlsConfig, needTLS: true, user: "upkeep", password: password},
			cfg: func(c *Config) {
				c.StartTLS, c.CAFile, c.User, c.PasswordFile = true, caFile, "upkeep", wrongPasswordFile
			},
			wantErr: []string{"logging in as upkeep", "535"},
		},
		{
			name:  "a missing password file",
			relay: &relay{tls: tlsConfig, needTLS: true, user: "upkeep", password: password},
			cfg: func(c *Config) {
				c.StartTLS, c.CAFile, c.User, c.PasswordFile = true, caFile, "upkeep", "/nonexistent/password"
			},
			wantErr:  []string{"reading password_file"},
			neverSaw: []string{"AUTH", "MAIL"},
		},
		{
			name:     "a certificate nobody vouches for stops everything before the login",
			relay:    &relay{tls: tlsConfig, needTLS: true, user: "upkeep", password: password},
			cfg:      func(c *Config) { c.StartTLS, c.User, c.PasswordFile = true, "upkeep", passwordFile },
			wantErr:  []string{"starting TLS", "certificate"},
			neverSaw: []string{"AUTH", "MAIL"},
		},
		{
			name:     "STARTTLS asked for, the relay has none",
			cfg:      func(c *Config) { c.StartTLS = true },
			wantErr:  []string{"does not offer"},
			neverSaw: []string{"MAIL"},
		},
		{
			name:     "a login without STARTTLS is refused before anything is sent",
			relay:    &relay{user: "upkeep", password: password},
			cfg:      func(c *Config) { c.User, c.PasswordFile = "upkeep", passwordFile },
			wantErr:  []string{"starttls"},
			neverSaw: []string{"EHLO", "AUTH"},
		},
		{
			name:    "a relay that demands STARTTLS says so",
			relay:   &relay{tls: tlsConfig, needTLS: true},
			wantErr: []string{"naming the sender upkeep@example.net", "530", "STARTTLS"},
		},
		{
			name:    "a relay that demands a login says so",
			relay:   &relay{tls: tlsConfig, user: "upkeep", password: password},
			wantErr: []string{"naming the sender", "Authentication required"},
		},
		{
			name:    "a refused recipient",
			cfg:     func(c *Config) { c.To = append(c.To, "nobody@example.net") },
			wantErr: []string{"naming the recipient nobody@example.net", "550"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.relay == nil {
				tt.relay = &relay{}
			}
			r := startRelay(t, tt.relay)
			cfg := Config{SMTP: r.addr(), From: "Upkeep <upkeep@example.net>", To: []string{"owner@example.net", "Žarko <second@example.net>"}}
			if tt.cfg != nil {
				tt.cfg(&cfg)
			}
			err := Send(t.Context(), cfg, testSubject, testText, testHTML)

			for _, c := range tt.neverSaw {
				if r.saw(c) {
					t.Errorf("the relay received %s", c)
				}
			}
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatal("no error")
				}
				for _, part := range tt.wantErr {
					if !strings.Contains(err.Error(), part) {
						t.Errorf("error %q does not say %q", err, part)
					}
				}
				for _, secret := range []string{password, "not the password"} {
					if strings.Contains(err.Error(), secret) {
						t.Errorf("the error contains a password: %q", err)
					}
				}
				if n := len(r.delivered()); n != 0 {
					t.Errorf("%d mails arrived although Send failed", n)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			mails := r.delivered()
			if len(mails) != 1 {
				t.Fatalf("%d mails arrived, want 1", len(mails))
			}
			m := mails[0]
			if m.from != "upkeep@example.net" || strings.Join(m.to, " ") != "owner@example.net second@example.net" {
				t.Errorf("envelope: from %q to %q", m.from, m.to)
			}
			if m.secured != tt.secured || m.user != tt.user {
				t.Errorf("secured = %v, logged in as %q; want %v, %q", m.secured, m.user, tt.secured, tt.user)
			}
			if tt.user != "" && !r.saw("AUTH PLAIN "+tt.user+" "+password) {
				t.Errorf("the password did not arrive as it is in the file (without its line end)")
			}
			checkMessage(t, m.data)
		})
	}
}

// checkMessage reads a delivered mail the way a mail program does and compares it with what
// was sent.
func checkMessage(t *testing.T, data []byte) {
	t.Helper()
	for line := range bytes.SplitSeq(data, []byte("\r\n")) {
		if len(line) > 78 {
			t.Errorf("a line of %d characters: %q", len(line), line)
		}
		if bytes.ContainsAny(line, "\r\n") {
			t.Errorf("a line end that is not CRLF in %q", line)
		}
		for _, b := range line {
			if b > 126 {
				t.Errorf("a byte that is not ASCII in %q", line)
				break
			}
		}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	header := func(name string) string {
		v, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get(name))
		if err != nil {
			t.Errorf("header %s: %v", name, err)
		}
		return v
	}
	if got := header("Subject"); got != testSubject {
		t.Errorf("Subject = %q, want %q", got, testSubject)
	}
	if got := header("From"); got != `"Upkeep" <upkeep@example.net>` {
		t.Errorf("From = %q", got)
	}
	if to, err := msg.Header.AddressList("To"); err != nil || len(to) != 2 || to[1].Name != "Žarko" || to[1].Address != "second@example.net" {
		t.Errorf("To = %v, %v", to, err)
	}
	if _, err := msg.Header.Date(); err != nil {
		t.Errorf("Date: %v", err)
	}
	if id := msg.Header.Get("Message-ID"); !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@example.net>") {
		t.Errorf("Message-ID = %q", id)
	}
	kind, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || kind != "multipart/alternative" {
		t.Fatalf("Content-Type = %q, %v", kind, err)
	}
	parts := multipart.NewReader(msg.Body, params["boundary"])
	for _, want := range []struct{ kind, content string }{{"text/plain", testText}, {"text/html", testHTML}} {
		p, err := parts.NextRawPart()
		if err != nil {
			t.Fatalf("%s part: %v", want.kind, err)
		}
		if got := p.Header.Get("Content-Type"); got != want.kind+"; charset=utf-8" {
			t.Errorf("part type = %q, want %s in UTF-8", got, want.kind)
		}
		if got := p.Header.Get("Content-Transfer-Encoding"); got != "quoted-printable" {
			t.Errorf("part encoding = %q", got)
		}
		body, err := io.ReadAll(quotedprintable.NewReader(p))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.ReplaceAll(string(body), "\r\n", "\n"); got != want.content {
			t.Errorf("%s part differs\n got: %q\nwant: %q", want.kind, got, want.content)
		}
	}
	if _, err := parts.NextRawPart(); err != io.EOF {
		t.Errorf("more than two parts: %v", err)
	}
}

func TestSendSubjectIsOneHeader(t *testing.T) {
	r := startRelay(t, &relay{})
	cfg := Config{SMTP: r.addr(), From: "upkeep@example.net", To: []string{"owner@example.net"}}
	if err := Send(t.Context(), cfg, "upkeep: 1 warning\r\nBcc: thief@example.org\r\n\r\ninjected body", "text", ""); err != nil {
		t.Fatal(err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(r.delivered()[0].data))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Bcc") != "" {
		t.Error("a line break in the subject became a header of its own")
	}
	if got := msg.Header.Get("Subject"); got != "upkeep: 1 warning Bcc: thief@example.org injected body" {
		t.Errorf("Subject = %q", got)
	}
}

// The connection's deadline is the context's, and its read can time out an instant before the
// context reports the deadline: seen once on a CI runner as "i/o timeout" where the deadline
// was expected.
func TestWhyStopped(t *testing.T) {
	timedOut := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	wrapped := errors.Join(errors.New("reading the greeting"), timedOut)
	other := errors.New("554 no thanks")

	if got := whyStopped(t.Context(), wrapped); !errors.Is(got, context.DeadlineExceeded) {
		t.Errorf("a read that timed out under a context still alive: %v, want the deadline", got)
	}
	if got := whyStopped(t.Context(), other); got != other {
		t.Errorf("an answer of the relay under a context still alive: %v, want it unchanged", got)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if got := whyStopped(cancelled, other); !errors.Is(got, context.Canceled) {
		t.Errorf("under a cancelled context: %v, want the cancellation", got)
	}
}

func TestSendGivesUp(t *testing.T) {
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	nobody := gone.Addr().String()
	gone.Close() // nothing listens there now

	t.Run("nobody listens", func(t *testing.T) {
		cfg := Config{SMTP: nobody, From: "upkeep@example.net", To: []string{"owner@example.net"}}
		err := Send(t.Context(), cfg, "s", "t", "h")
		if err == nil || !strings.Contains(err.Error(), "connecting to the relay "+nobody) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("the relay never answers", func(t *testing.T) {
		r := startRelay(t, &relay{mute: true})
		cfg := Config{SMTP: r.addr(), From: "upkeep@example.net", To: []string{"owner@example.net"}}
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		err := Send(ctx, cfg, "s", "t", "h")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want the deadline", err)
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("gave up only after %v", took)
		}
	})
	t.Run("the server shuts down while sending", func(t *testing.T) {
		r := startRelay(t, &relay{mute: true})
		cfg := Config{SMTP: r.addr(), From: "upkeep@example.net", To: []string{"owner@example.net"}}
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(50*time.Millisecond, cancel)
		start := time.Now()
		err := Send(ctx, cfg, "s", "t", "h")
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want cancelled", err)
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("stopped only after %v", took)
		}
	})
	t.Run("no relay configured", func(t *testing.T) {
		if err := Send(t.Context(), Config{}, "s", "t", "h"); err == nil {
			t.Error("no error")
		}
	})
}

// TestSendThroughARealRelay is for a person with a relay at hand, not for "go test": it sends
// one digest through UPKEEP_TEST_SMTP (host:port, plain SMTP) to UPKEEP_TEST_TO.
func TestSendThroughARealRelay(t *testing.T) {
	smtp, to := os.Getenv("UPKEEP_TEST_SMTP"), os.Getenv("UPKEEP_TEST_TO")
	if smtp == "" || to == "" {
		t.Skip("set UPKEEP_TEST_SMTP and UPKEEP_TEST_TO to send a real mail")
	}
	cfg := Config{SMTP: smtp, From: "Upkeep <upkeep@example.net>", To: []string{to},
		StartTLS: os.Getenv("UPKEEP_TEST_STARTTLS") != "", CAFile: os.Getenv("UPKEEP_TEST_CA"),
		User: os.Getenv("UPKEEP_TEST_USER"), PasswordFile: os.Getenv("UPKEEP_TEST_PASSWORD_FILE")}
	if err := Send(t.Context(), cfg, testSubject, testText, testHTML); err != nil {
		t.Fatal(err)
	}
}
