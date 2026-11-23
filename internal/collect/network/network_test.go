package network

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/valicm/upkeep/internal/report"
)

func ipnet(s string) *net.IPNet {
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return n
}

// The server of the homelab this was written for: a LAN address, four service addresses on the
// same card, a Podman bridge, and a link that is down.
func serverInterfaces() ([]iface, error) {
	return []iface{
		{name: "lo", up: true, loopback: true, addrs: []*net.IPNet{ipnet("127.0.0.1/8"), ipnet("::1/128")}},
		{name: "podman0", up: true, addrs: []*net.IPNet{ipnet("10.88.0.1/16")}},
		{name: "veth3a1b2c", up: true, addrs: []*net.IPNet{ipnet("fe80::1c2b:3aff:fe4d:5e6f/64")}},
		{name: "enp73s0", up: true, addrs: []*net.IPNet{
			ipnet("10.10.10.5/24"), ipnet("10.10.10.12/24"), ipnet("10.10.10.13/24"),
			ipnet("fe80::3eec:efff:fe12:3456/64"), ipnet("fd00:10::5/64"),
		}},
		{name: "enp74s0", up: false, addrs: []*net.IPNet{ipnet("192.168.99.1/24")}},
	}, nil
}

func TestCollect(t *testing.T) {
	var asked string
	c := &collector{
		enabled:    true,
		server:     "http://10.10.10.40:8484",
		root:       "testdata/sshd-include",
		interfaces: serverInterfaces,
		hostname:   func() (string, error) { return "server\n", nil },
		localAddr: func(_ context.Context, hostport string) (net.IP, error) {
			asked = hostport
			return net.ParseIP("10.10.10.5"), nil
		},
	}
	var r report.Report
	if err := c.Collect(context.Background(), &r); err != nil {
		t.Fatal(err)
	}
	want := &report.Network{
		Hostname: "server",
		Primary:  "10.10.10.5",
		Addresses: []report.Address{
			{Interface: "enp73s0", IP: "10.10.10.5", Prefix: 24},
			{Interface: "enp73s0", IP: "10.10.10.12", Prefix: 24},
			{Interface: "enp73s0", IP: "10.10.10.13", Prefix: 24},
			{Interface: "enp73s0", IP: "fd00:10::5", Prefix: 64},
		},
		SSHPorts: []int{2222},
	}
	if !reflect.DeepEqual(r.System.Network, want) {
		t.Errorf("got  %+v\nwant %+v", r.System.Network, want)
	}
	if asked != "10.10.10.40:8484" {
		t.Errorf("asked the route to %q, want the server's address and port", asked)
	}
}

func TestDisabled(t *testing.T) {
	off := false
	c := New(Config{Enabled: &off}, "http://hub")
	var r report.Report
	if err := c.Collect(context.Background(), &r); err != nil || r.System.Network != nil {
		t.Errorf("a disabled collector filled %+v (err %v)", r.System.Network, err)
	}
}

func TestInterfacesFail(t *testing.T) {
	c := &collector{enabled: true, interfaces: func() ([]iface, error) { return nil, errors.New("netlink refused") }}
	var r report.Report
	if err := c.Collect(context.Background(), &r); err == nil {
		t.Error("no error when the interfaces cannot be listed")
	}
}

func TestPrimary(t *testing.T) {
	for _, tc := range []struct {
		server, wantAsked, got, want string
		fail                         bool
	}{
		{server: "https://upkeep.example.net", wantAsked: "upkeep.example.net:443", got: "10.10.10.40", want: "10.10.10.40"},
		{server: "http://upkeep.example.net/", wantAsked: "upkeep.example.net:80", got: "10.10.10.40", want: "10.10.10.40"},
		{server: "http://[fd00::40]:8484", wantAsked: "[fd00::40]:8484", got: "fd00::5", want: "fd00::5"},
		// The server on this very machine, through loopback: no address to show.
		{server: "http://127.0.0.1:8484", wantAsked: "127.0.0.1:8484", got: "127.0.0.1", want: ""},
		{server: "http://upkeep.example.net", wantAsked: "upkeep.example.net:80", fail: true, want: ""},
		{server: "", want: ""},
	} {
		var asked string
		c := &collector{server: tc.server, localAddr: func(_ context.Context, hp string) (net.IP, error) {
			asked = hp
			if tc.fail {
				return nil, errors.New("no route")
			}
			return net.ParseIP(tc.got), nil
		}}
		if got := c.primary(context.Background()); got != tc.want || asked != tc.wantAsked {
			t.Errorf("%q: got %q after asking %q, want %q after asking %q", tc.server, got, asked, tc.want, tc.wantAsked)
		}
	}
}

func TestSSHPorts(t *testing.T) {
	for _, tc := range []struct {
		root string
		want []int
	}{
		// 2222 and 2200 configured (one through Include), only 2222 listens; 22 has an
		// established connection but no listener.
		{"testdata/sshd-include", []int{2222}},
		// No Port line: 22, listening on IPv6 only.
		{"testdata/sshd-default", []int{22}},
		// No sshd_config, but 22 listens.
		{"testdata/no-sshd", []int{22}},
		// Nothing at all.
		{"testdata/missing", nil},
	} {
		if got := sshPorts(tc.root); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.root, got, tc.want)
		}
	}
}

func TestSplitDirective(t *testing.T) {
	for in, want := range map[string][2]string{
		"Port 22":          {"Port", "22"},
		"Port=2222":        {"Port", "2222"},
		"port\t 2200":      {"port", "2200"},
		"ListenAddress":    {"ListenAddress", ""},
		"Include a.conf b": {"Include", "a.conf b"},
	} {
		k, v := splitDirective(in)
		if k != want[0] || v != want[1] {
			t.Errorf("%q: got %q %q, want %q %q", in, k, v, want[0], want[1])
		}
	}
}
