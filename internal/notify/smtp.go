package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strings"
	"time"
)

// sendTimeout is how long the whole conversation with the relay may take.
const sendTimeout = time.Minute

// Send delivers a rendered digest through the relay in cfg. By default it speaks plain SMTP
// without a login, which is what a relay on the LAN wants; with starttls it encrypts first and
// then logs in when a user is set. It never logs in on a connection that is not encrypted.
func Send(ctx context.Context, cfg Config, subject, text, html string) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("sending mail: %w", err)
	}
	if !cfg.Enabled() {
		return errors.New("sending mail: no smtp relay is configured")
	}
	from, _ := mail.ParseAddress(cfg.From) // Validate parsed these already
	var to []*mail.Address
	for _, s := range cfg.To {
		a, _ := mail.ParseAddress(s)
		to = append(to, a)
	}
	msg, err := message(from, to, subject, text, html, time.Now())
	if err != nil {
		return fmt.Errorf("sending mail: building the message: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", cfg.SMTP)
	if err != nil {
		return fmt.Errorf("sending mail: connecting to the relay %s: %w", cfg.SMTP, err)
	}
	defer conn.Close()
	// net/smtp knows no context. The deadline bounds every read and write, and closing the
	// connection ends them at once when the context is cancelled, as on shutdown.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if err := converse(conn, cfg, from.Address, to, msg); err != nil {
		return fmt.Errorf("sending mail through %s: %w", cfg.SMTP, whyStopped(ctx, err))
	}
	return nil
}

// whyStopped names the end of the context as the reason a conversation failed, when it was.
// A closed connection says "use of closed network connection", which would hide why. And the
// connection's deadline is the context's own, so a read can time out an instant before the
// context itself reports that its deadline passed.
func whyStopped(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return err
}

// converse is the SMTP conversation on a connection that is already open.
func converse(conn net.Conn, cfg Config, from string, to []*mail.Address, msg []byte) error {
	host, _, _ := net.SplitHostPort(cfg.SMTP)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("reading the greeting: %w", err)
	}
	defer c.Close()
	if err := c.Hello(helloName()); err != nil {
		return fmt.Errorf("saying hello: %w", err)
	}
	if cfg.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("starttls is asked for but the relay does not offer it")
		}
		tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return fmt.Errorf("reading ca_file: %w", err)
			}
			tc.RootCAs = x509.NewCertPool()
			if !tc.RootCAs.AppendCertsFromPEM(pem) {
				return fmt.Errorf("ca_file %s holds no certificate", cfg.CAFile)
			}
		}
		if err := c.StartTLS(tc); err != nil {
			return fmt.Errorf("starting TLS: %w", err)
		}
	}
	if cfg.User != "" { // Validate made sure that STARTTLS came first
		raw, err := os.ReadFile(cfg.PasswordFile)
		if err != nil {
			return fmt.Errorf("reading password_file: %w", err)
		}
		password := strings.TrimRight(string(raw), "\r\n")
		if password == "" {
			return fmt.Errorf("password_file %s is empty", cfg.PasswordFile)
		}
		// The relay's answer is in the error, the password never is.
		if err := c.Auth(smtp.PlainAuth("", cfg.User, password, host)); err != nil {
			return fmt.Errorf("logging in as %s: %w", cfg.User, err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("naming the sender %s: %w", from, err)
	}
	for _, a := range to {
		if err := c.Rcpt(a.Address); err != nil {
			return fmt.Errorf("naming the recipient %s: %w", a.Address, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("starting the message: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("writing the message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finishing the message: %w", err)
	}
	// The relay has the mail now. A failed goodbye must not turn that into an error, or the
	// same digest would be sent again.
	c.Quit()
	return nil
}

// helloName is how the server introduces itself. Relays that check it want a host name.
func helloName() string {
	if name, err := os.Hostname(); err == nil && name != "" && !strings.ContainsAny(name, " \r\n") {
		return name
	}
	return "localhost"
}

// message builds the mail: both forms of the digest as alternatives, so a mail program shows
// the HTML and a terminal the text. Everything is encoded to 7-bit lines of at most 76
// characters, which every relay passes on unchanged.
func message(from *mail.Address, to []*mail.Address, subject, text, html string, now time.Time) ([]byte, error) {
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	domain := "localhost"
	if at := strings.LastIndexByte(from.Address, '@'); at >= 0 && at < len(from.Address)-1 {
		domain = from.Address[at+1:]
	}
	recipients := make([]string, len(to))
	for i, a := range to {
		recipients[i] = a.String()
	}

	var body bytes.Buffer
	parts := multipart.NewWriter(&body)
	for _, p := range []struct{ kind, content string }{{"text/plain", text}, {"text/html", html}} {
		if p.content == "" {
			continue
		}
		w, err := parts.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {p.kind + "; charset=utf-8"},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		qp := quotedprintable.NewWriter(w) // also turns every line end into CRLF
		if _, err := qp.Write([]byte(p.content)); err != nil {
			return nil, err
		}
		if err := qp.Close(); err != nil {
			return nil, err
		}
	}
	if err := parts.Close(); err != nil {
		return nil, err
	}

	var msg bytes.Buffer
	header := func(name, value string) { msg.WriteString(name + ": " + value + "\r\n") }
	header("From", from.String())
	header("To", strings.Join(recipients, ",\r\n "))
	// A subject is one line whatever it is made from; Q-encoding covers what is not ASCII.
	header("Subject", mime.QEncoding.Encode("utf-8", strings.Join(strings.Fields(subject), " ")))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id[:])+"@"+domain+">")
	header("Auto-Submitted", "auto-generated") // keeps vacation responders quiet
	header("MIME-Version", "1.0")
	header("Content-Type", "multipart/alternative;\r\n boundary=\""+parts.Boundary()+"\"")
	msg.WriteString("\r\n")
	msg.Write(body.Bytes())
	return msg.Bytes(), nil
}
