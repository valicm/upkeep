// Package network says how a machine is reached: the addresses of its interfaces, the one it
// reaches the upkeep server from, and the ports an SSH server listens on. It asks the kernel for
// the interfaces and reads files; nothing of it needs privileges.
package network

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/valicm/upkeep/internal/collect"
	"github.com/valicm/upkeep/internal/report"
)

// Config is the [network] table of the agent's configuration.
type Config struct {
	Enabled *bool `toml:"enabled"` // true unless set to false
}

// dialTimeout bounds finding the address that reaches the server. Nothing is sent: a UDP
// socket is only connected, which asks the kernel for a route. A name may need DNS, though.
const dialTimeout = 5 * time.Second

// Interfaces whose names start like these belong to containers and virtual machines: their
// addresses are not the machine's own, and a host with many containers would list dozens.
var skipPrefixes = []string{
	"veth", "podman", "cni", "docker", "br-", "virbr", "vnet", "lxc", "cali", "flannel",
	"kube", "cilium", "vxlan", "tap",
}

// iface is what the collector needs of one network interface.
type iface struct {
	name     string
	up       bool
	loopback bool
	addrs    []*net.IPNet
}

type collector struct {
	enabled    bool
	server     string // the upkeep server's URL
	root       string // "" on a real machine, a testdata directory in tests
	interfaces func() ([]iface, error)
	hostname   func() (string, error)
	localAddr  func(ctx context.Context, hostport string) (net.IP, error)
}

// New returns the collector. server is the URL the agent reports to.
func New(cfg Config, server string) collect.Collector {
	return &collector{
		enabled:    cfg.Enabled == nil || *cfg.Enabled,
		server:     server,
		interfaces: systemInterfaces,
		hostname:   os.Hostname,
		localAddr:  localAddr,
	}
}

func (*collector) Name() string { return "network" }

// Collect fills r.System.Network. Only the interfaces are needed: what else is missing stays
// empty.
func (c *collector) Collect(ctx context.Context, r *report.Report) error {
	if !c.enabled {
		return nil
	}
	ifs, err := c.interfaces()
	if err != nil {
		return fmt.Errorf("listing the network interfaces: %w", err)
	}
	n := &report.Network{}
	if h, err := c.hostname(); err == nil {
		n.Hostname = strings.TrimSpace(h)
	}
	n.Addresses = addresses(ifs)
	n.Primary = c.primary(ctx)
	n.SSHPorts = sshPorts(c.root)
	r.System.Network = n
	return nil
}

// addresses keeps the machine's own: no loopback, no link-local addresses, no interfaces of
// containers, nothing on an interface that is down. They come sorted by interface, with the
// interface's own order of addresses kept.
func addresses(ifs []iface) []report.Address {
	sort.SliceStable(ifs, func(i, j int) bool { return ifs[i].name < ifs[j].name })
	var out []report.Address
	for _, f := range ifs {
		if !f.up || f.loopback || skipped(f.name) {
			continue
		}
		for _, a := range f.addrs {
			ip := a.IP
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			ones, _ := a.Mask.Size()
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			out = append(out, report.Address{Interface: f.name, IP: ip.String(), Prefix: ones})
		}
	}
	return out
}

func skipped(name string) bool {
	for _, p := range skipPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// primary is the address this machine reaches the upkeep server from: the one its route to
// the server leaves by. Empty when the server is this machine's loopback, or not reachable.
func (c *collector) primary(ctx context.Context) string {
	u, err := url.Parse(c.server)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	ip, err := c.localAddr(ctx, net.JoinHostPort(u.Hostname(), port))
	if err != nil || ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.String()
}

func localAddr(ctx context.Context, hostport string) (net.IP, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", hostport)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP, nil
	}
	return nil, fmt.Errorf("unexpected local address %v", conn.LocalAddr())
}

func systemInterfaces() ([]iface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []iface
	for _, f := range list {
		addrs, err := f.Addrs()
		if err != nil {
			continue // gone since the list was made
		}
		one := iface{name: f.Name, up: f.Flags&net.FlagUp != 0, loopback: f.Flags&net.FlagLoopback != 0}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				one.addrs = append(one.addrs, n)
			}
		}
		out = append(out, one)
	}
	return out, nil
}

// sshPorts returns the ports sshd is configured for that something listens on. Without a
// readable sshd_config, port 22 counts when something listens there.
func sshPorts(root string) []int {
	listening := listeningTCP(root)
	configured, ok := sshdConfigPorts(root)
	if !ok {
		configured = []int{22}
	}
	var out []int
	seen := map[int]bool{}
	for _, p := range configured {
		if listening[p] && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// listeningTCP reads the kernel's socket tables: the ports that have a socket in LISTEN.
func listeningTCP(root string) map[int]bool {
	out := map[int]bool{}
	for _, name := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Scan() // the header
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) < 4 || f[3] != "0A" { // 0A is LISTEN
				continue
			}
			_, port, ok := strings.Cut(f[1], ":")
			if !ok {
				continue
			}
			pb, err := hex.DecodeString(port)
			if err != nil || len(pb) != 2 {
				continue
			}
			out[int(pb[0])<<8|int(pb[1])] = true
		}
	}
	return out
}

// sshdConfigPorts reads sshd_config and the files it includes, for Port and for ListenAddress
// with a port. ok is false when the file cannot be read; a file that names no port means 22.
func sshdConfigPorts(root string) (ports []int, ok bool) {
	main := "/etc/ssh/sshd_config"
	if _, err := os.Stat(filepath.Join(root, main)); err != nil {
		return nil, false
	}
	seen := map[string]bool{}
	var read func(path string, depth int) bool
	read = func(path string, depth int) bool {
		if depth > 8 || seen[path] {
			return true
		}
		seen[path] = true
		b, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			return false
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value := splitDirective(line)
			switch strings.ToLower(key) {
			case "port":
				if p, err := strconv.Atoi(value); err == nil && p > 0 && p < 65536 {
					ports = append(ports, p)
				}
			case "listenaddress":
				// "host:port", "[v6]:port", or an address alone.
				host := strings.Fields(value)
				if len(host) == 0 {
					continue
				}
				if _, p, err := net.SplitHostPort(host[0]); err == nil {
					if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
						ports = append(ports, n)
					}
				}
			case "include":
				for _, pattern := range strings.Fields(value) {
					if !filepath.IsAbs(pattern) {
						pattern = filepath.Join("/etc/ssh", pattern)
					}
					matches, _ := filepath.Glob(filepath.Join(root, pattern))
					sort.Strings(matches)
					for _, m := range matches {
						read(strings.TrimPrefix(m, root), depth+1)
					}
				}
			}
		}
		return true
	}
	if !read(main, 0) {
		return nil, false
	}
	if len(ports) == 0 {
		ports = []int{22}
	}
	return ports, true
}

// splitDirective splits "Port 22" and "Port=22" into the keyword and the rest.
func splitDirective(line string) (string, string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
}
