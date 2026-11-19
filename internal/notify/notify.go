// Package notify sends the digest mail: the same findings the dashboard shows.
package notify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/model"
)

// Config is the [mail] table of the server's configuration. Without it, or without smtp, no
// mail is sent.
type Config struct {
	SMTP     string   `toml:"smtp"`     // "192.0.2.25:1025"
	From     string   `toml:"from"`     // "upkeep@example.net" or "Upkeep <upkeep@example.net>"
	To       []string `toml:"to"`       // one or more addresses
	URL      string   `toml:"url"`      // the dashboard's address, for the link in the mail
	Schedule string   `toml:"schedule"` // "daily 07:00" (the default), "weekly mon 07:00" or "on change"

	// A relay on the LAN needs none of these. One on the internet does.
	StartTLS     bool   `toml:"starttls"`      // encrypt the connection before sending; required for a login
	User         string `toml:"user"`          // log in as this user
	PasswordFile string `toml:"password_file"` // a file holding that user's password
	CAFile       string `toml:"ca_file"`       // certificates (PEM) to trust for the relay, when a private CA signed its own
}

// Enabled reports whether the configuration asks for mail at all.
func (c Config) Enabled() bool { return c.SMTP != "" }

// Validate checks a configuration that asks for mail, so that a mistake is found when the
// server starts and not at seven in the morning.
func (c Config) Validate() error {
	if !c.Enabled() {
		return nil
	}
	if _, _, err := net.SplitHostPort(c.SMTP); err != nil {
		return fmt.Errorf("smtp must be host:port, like \"192.0.2.25:1025\": %w", err)
	}
	if _, err := mail.ParseAddress(c.From); err != nil {
		return fmt.Errorf("from %q is not a mail address: %w", c.From, err)
	}
	if len(c.To) == 0 {
		return errors.New("to needs at least one address")
	}
	for _, to := range c.To {
		if _, err := mail.ParseAddress(to); err != nil {
			return fmt.Errorf("to %q is not a mail address: %w", to, err)
		}
	}
	if _, err := ParseSchedule(c.Schedule); err != nil {
		return err
	}
	if c.URL != "" {
		// It becomes a link in a mail: only a web address may be one.
		if u, err := url.Parse(c.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("url %q must be an http or https address", c.URL)
		}
	}
	switch {
	case c.User != "" && c.PasswordFile == "":
		return errors.New("user needs password_file")
	case c.User == "" && c.PasswordFile != "":
		return errors.New("password_file needs user")
	case c.User != "" && !c.StartTLS:
		return errors.New("a login needs starttls = true: the password must not travel in the clear")
	case c.CAFile != "" && !c.StartTLS:
		return errors.New("ca_file needs starttls = true")
	}
	return nil
}

// Fingerprint identifies a set of findings: it changes when a finding appears, goes away or
// changes its severity or title, and not with time alone, because titles carry no ages and
// details are left out. An empty set has a fingerprint too, so "" can mean "never mailed".
func Fingerprint(findings []model.Finding) string {
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, strings.Join([]string{f.System, string(f.Category), strconv.Itoa(int(f.Severity)), f.Title}, "\x00"))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// digest is what both templates are filled with.
type digest struct {
	Summary string
	Groups  []group
	Quiet   string // the systems with nothing to do, in one line
	URL     string
	Stamp   string
}

type group struct {
	System   string
	Findings []line
}

type line struct {
	Label  string       // "crit", "warn", "info": all four letters, so plain text lines up
	Style  template.CSS // the label's colour in the HTML mail
	Title  string
	Detail string
}

var labelStyles = map[model.Severity]template.CSS{
	model.Crit: "color:#b3261e",
	model.Warn: "color:#9a6700",
	model.Info: "color:#57606a",
}

// Render builds the digest: subject, plain text and HTML. Findings are grouped by system in
// the order they come, so the system with the worst finding is on top.
func Render(cfg Config, states []model.SystemState, findings []model.Finding, now time.Time) (subject, text, html string) {
	d := digest{URL: cfg.URL, Stamp: now.Format("2006-01-02 15:04 MST")}
	index := map[string]int{}
	var counts [3]int
	for _, f := range findings {
		i, ok := index[f.System]
		if !ok {
			i = len(d.Groups)
			index[f.System] = i
			d.Groups = append(d.Groups, group{System: f.System})
		}
		// A severity this version does not know is at least critical, or it would not have
		// been added to the scale; it must not take the mail down either way.
		sev := min(max(f.Severity, model.Info), model.Crit)
		d.Groups[i].Findings = append(d.Groups[i].Findings, line{
			Label: sev.String(), Style: labelStyles[sev], Title: f.Title, Detail: f.Detail,
		})
		counts[sev]++
	}
	var quiet []string
	for _, st := range states {
		if _, ok := index[st.Report.System.Name]; !ok {
			quiet = append(quiet, st.Report.System.Name)
		}
	}

	if len(findings) == 0 {
		subject = "upkeep: nothing needs attention"
		switch len(states) {
		case 0:
			d.Summary = "Nothing needs attention, but no system has reported yet."
		default:
			d.Summary = fmt.Sprintf("Nothing needs attention on %s.", plural(len(states), "system"))
		}
	} else {
		var parts []string
		if n := counts[model.Crit]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d critical", n))
		}
		if n := counts[model.Warn]; n > 0 {
			parts = append(parts, plural(n, "warning"))
		}
		if n := counts[model.Info]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d info", n))
		}
		counted := strings.Join(parts, ", ")
		subject = "upkeep: " + counted
		if len(quiet) > 0 {
			d.Summary = fmt.Sprintf("%s on %d of %d systems.", counted, len(d.Groups), len(d.Groups)+len(quiet))
		} else {
			d.Summary = counted + " on " + plural(len(d.Groups), "system") + "."
		}
		d.Quiet = strings.Join(quiet, ", ")
	}

	return subject, renderText(d), renderHTML(d, subject)
}

func renderText(d digest) string {
	var b strings.Builder
	b.WriteString(d.Summary + "\n")
	for _, g := range d.Groups {
		b.WriteString("\n" + g.System + "\n")
		for _, l := range g.Findings {
			b.WriteString("  " + l.Label + "  " + l.Title + "\n")
			if l.Detail != "" {
				b.WriteString("        " + l.Detail + "\n")
			}
		}
	}
	if d.Quiet != "" {
		b.WriteString("\nNothing to do on: " + d.Quiet + ".\n")
	}
	b.WriteString("\n")
	if d.URL != "" {
		b.WriteString("Dashboard: " + d.URL + "\n")
	}
	b.WriteString("upkeep, " + d.Stamp + "\n")
	return b.String()
}

// The HTML is what mail programs agree on: tables and inline styles, nothing loaded from
// anywhere. html/template escapes every value, so a hostile package name stays text.
var htmlTemplate = template.Must(template.New("digest").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{{.Subject}}</title></head>
<body style="margin:0;padding:16px;font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;line-height:1.4;color:#1f2328">
<p style="margin:0 0 12px">{{.Summary}}</p>
{{range .Groups}}<h2 style="margin:18px 0 6px;font-size:16px">{{.System}}</h2>
<table cellpadding="0" cellspacing="0" style="border-collapse:collapse">
{{range .Findings}}<tr>
<td style="padding:3px 12px 3px 0;vertical-align:top;white-space:nowrap;font-weight:bold;{{.Style}}">{{.Label}}</td>
<td style="padding:3px 0;vertical-align:top">{{.Title}}{{with .Detail}}<br><span style="font-size:13px;color:#57606a">{{.}}</span>{{end}}</td>
</tr>
{{end}}</table>
{{end}}{{with .Quiet}}<p style="margin:18px 0 0;color:#57606a">Nothing to do on: {{.}}.</p>
{{end}}<p style="margin:18px 0 0;font-size:13px;color:#57606a">{{with .URL}}<a href="{{.}}">{{.}}</a><br>{{end}}upkeep, {{.Stamp}}</p>
</body>
</html>
`))

func renderHTML(d digest, subject string) string {
	var b strings.Builder
	err := htmlTemplate.Execute(&b, struct {
		digest
		Subject string
	}{d, subject})
	if err != nil {
		// The template is fixed and its data plain strings: this cannot happen. If it does,
		// the plain text part still says everything.
		return ""
	}
	return b.String()
}

func plural(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}
