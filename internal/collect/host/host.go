// Package host says what machine the agent runs on: the operating system and its version, the
// running kernel and the architecture. It reads files only, plus "uname -r" where the kernel
// does not publish its release as a file.
package host

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/collect"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/version"
)

// Config is this collector's part of the agent's configuration file. It has nothing to set.
type Config struct{}

// unameTimeout is generous for a command that only prints one line.
const unameTimeout = 5 * time.Second

type collector struct {
	root  string // "" on a real machine, a testdata directory in tests
	goos  string
	arch  string
	uname func(ctx context.Context) (string, error)
}

// New returns the collector.
func New(Config) collect.Collector {
	return &collector{goos: runtime.GOOS, arch: runtime.GOARCH, uname: Uname}
}

func (*collector) Name() string { return "host" }

// Collect fills r.System, except the name: that is the agent's to choose. A file that is
// missing leaves its field empty and is never an error: the report is still worth sending.
func (c *collector) Collect(ctx context.Context, r *report.Report) error {
	s := &r.System
	s.Kind = c.goos
	s.Source = "agent"
	s.AgentVersion = version.String()
	// The architecture the agent was built for is the architecture of the userland it runs
	// in, and that is what packages and container images are chosen by. A 64-bit kernel under
	// a 32-bit Raspberry Pi OS is therefore "arm".
	s.Arch = c.arch

	rel := ReadOSRelease(c.root)
	s.OS = rel["PRETTY_NAME"]
	if s.OS == "" {
		s.OS = rel["NAME"]
	}
	s.OSVersion = osVersion(rel, firstLine(filepath.Join(c.root, "/etc/debian_version")))
	s.Kernel = Kernel(ctx, c.root, c.goos, c.uname)
	return nil
}

// osVersion picks the most exact version the system states about itself.
func osVersion(rel map[string]string, debianVersion string) string {
	debian := rel["ID"] == "debian" || rel["ID"] == "raspbian" // Raspberry Pi OS is one or the other
	switch {
	// os-release says "13" on Debian and cannot tell 13.2 from 13.7; /etc/debian_version
	// can. Ubuntu ships that file too, naming the Debian release it branched from
	// ("trixie/sid"), so it is only believed on Debian itself.
	case debian && debianVersion != "" && (isNumber(debianVersion) || rel["VERSION_ID"] == ""):
		return debianVersion // testing has no VERSION_ID: "forky/sid" is all there is
	// FreeBSD keeps the patch level in VERSION ("14.3-RELEASE-p7") and cuts it from VERSION_ID.
	case rel["ID"] == "freebsd" && rel["VERSION"] != "":
		return rel["VERSION"]
	case rel["VERSION_ID"] != "":
		return rel["VERSION_ID"]
	}
	return rel["VERSION"]
}

func isNumber(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

// ReadOSRelease returns the variables of os-release(5) under root ("" is the real machine).
// /usr/lib/os-release is the fallback the specification names. A machine with neither gives an
// empty map.
func ReadOSRelease(root string) map[string]string {
	out := map[string]string{}
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if k, v, ok := strings.Cut(line, "="); ok {
				out[k] = unquote(v)
			}
		}
		break
	}
	return out
}

// unquote removes the shell quoting os-release allows: quotes around the value, and inside
// double quotes a backslash before the few characters that need one.
func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) < 2 {
		return v
	}
	switch {
	case v[0] == '\'' && v[len(v)-1] == '\'':
		return v[1 : len(v)-1]
	case v[0] == '"' && v[len(v)-1] == '"':
		return strings.NewReplacer(`\"`, `"`, `\$`, `$`, "\\`", "`", `\\`, `\`).Replace(v[1 : len(v)-1])
	}
	return v
}

// Kernel returns the release of the running kernel, or "" when nothing tells. Linux publishes
// it as a file; elsewhere uname is asked.
func Kernel(ctx context.Context, root, goos string, uname func(context.Context) (string, error)) string {
	if goos == "linux" {
		if v := firstLine(filepath.Join(root, "/proc/sys/kernel/osrelease")); v != "" {
			return v
		}
	}
	ctx, cancel := context.WithTimeout(ctx, unameTimeout)
	defer cancel()
	v, err := uname(ctx)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// Uname runs "uname -r".
func Uname(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "uname", "-r")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second // do not wait for a pipe that a killed command left open
	out, err := cmd.Output()
	return string(out), err
}

func firstLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}
