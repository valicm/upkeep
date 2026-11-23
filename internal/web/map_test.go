package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/store"
)

// mapStore holds a server, a Raspberry Pi with an agent too old to report its network, and a
// firewall that is polled.
func mapStore(t *testing.T) store.Store {
	t.Helper()
	s := store.NewMemory()
	reps := []report.Report{
		{
			Schema: 1,
			System: report.System{
				Name: "server", Source: "agent", OS: "Debian GNU/Linux 13 (trixie)", OSVersion: "13.7",
				Network: &report.Network{
					Hostname: "server",
					Primary:  "10.10.10.5",
					Addresses: []report.Address{
						{Interface: "enp73s0", IP: "10.10.10.5", Prefix: 24},
						{Interface: "enp73s0", IP: "10.10.10.15", Prefix: 24},
					},
					SSHPorts: []int{22, 2200},
				},
			},
			Containers: []report.Container{
				{Name: "photoprism", Image: "docker.io/photoprism/photoprism:latest", Ports: []report.Port{
					{HostIP: "10.10.10.15", HostPort: 2342, Port: 2342, Protocol: "tcp"},
				}},
				{Name: "unifi", Image: "lscr.io/linuxserver/unifi:latest", Ports: []report.Port{
					{HostPort: 3478, Port: 3478, Protocol: "udp"},
					{HostPort: 8443, Port: 8443, Protocol: "tcp"},
				}},
				{Name: "gitea", Image: "docker.io/gitea/gitea:1.23.6", Ports: []report.Port{
					{HostIP: "10.10.10.12", HostPort: 2222, Port: 22, Protocol: "tcp"},
				}},
				{Name: "adguard", Image: "docker.io/adguard/adguardhome:latest", Network: "host"},
				// In unifi's network: the runtime lists unifi's ports for it too, the agent not.
				{Name: "sidecar", Image: "docker.io/library/alpine:3.20", Network: "container:unifi"},
				{Name: "worker", Image: "docker.io/library/alpine:3.20"},
			},
		},
		{Schema: 1, System: report.System{Name: "old-pi", Source: "agent", OS: "Debian GNU/Linux 12 (bookworm)"}},
		{Schema: 1, System: report.System{Name: "fw", Source: "connector", OS: "OPNsense", OSVersion: "26.10.1"}},
	}
	for i := range reps {
		if err := s.SaveReport(context.Background(), &reps[i], testNow.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func mapOptions() Map {
	return Map{
		SSHUser: "admin",
		Names: []MapName{
			{URL: "https://photos.example.net/", System: "server", Port: 2342},
			{URL: "https://unifi.example.net/", System: "server", Port: 8443},
			{URL: "https://server.example.net/", System: "server"},
			{URL: "https://nas.example.net/", System: "nas", Port: 5000}, // nas never reported
		},
		Appliances: []MapAppliance{{Name: "fw", URL: "https://fw.example.net:10000"}},
		Lookup: func(_ context.Context, host string) ([]string, error) {
			switch host {
			case "photos.example.net", "unifi.example.net":
				return []string{"10.10.11.1"}, nil
			case "fw.example.net":
				return []string{"10.10.10.1"}, nil
			case "server.example.net":
				return []string{"127.0.1.1"}, nil // the server's own name in its /etc/hosts
			}
			return nil, errors.New("no such host")
		},
	}
}

func TestBuildMap(t *testing.T) {
	st := mapStore(t)
	states, err := st.Systems(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snap := &snapshot{states: states, now: testNow}
	m := buildMap(context.Background(), snap, page{Root: "./"}, mapOptions(), mapOptions().Lookup)

	if len(m.Systems) != 3 || m.Systems[0].Name != "fw" || m.Systems[1].Name != "old-pi" || m.Systems[2].Name != "server" {
		t.Fatalf("systems: %+v", m.Systems)
	}
	fw, pi, srv := m.Systems[0], m.Systems[1], m.Systems[2]

	if fw.Primary != "10.10.10.1" || fw.Appliance != "https://fw.example.net:10000" || len(fw.SSH) != 0 {
		t.Errorf("the firewall, polled: %+v", fw)
	}
	if pi.Primary != "" || len(pi.SSH) != 0 || len(pi.Services) != 0 {
		t.Errorf("an agent without network facts shows nothing made up: %+v", pi)
	}

	if srv.Primary != "10.10.10.5" || len(srv.Others) != 1 || srv.Others[0].IP != "10.10.10.15" {
		t.Errorf("addresses: %q %+v", srv.Primary, srv.Others)
	}
	if strings.Join(srv.SSH, " | ") != "ssh admin@10.10.10.5 | ssh -p 2200 admin@10.10.10.5" {
		t.Errorf("SSH lines: %q", srv.SSH)
	}
	if srv.About != "Debian GNU/Linux 13 (trixie) 13.7" {
		t.Errorf("about: %q", srv.About)
	}
	var names []string
	for _, n := range srv.Names {
		names = append(names, n.Host+" "+n.IPs+" "+n.Service)
	}
	if want := "photos.example.net 10.10.11.1 photoprism|unifi.example.net 10.10.11.1 unifi|server.example.net  "; strings.Join(names, "|") != want {
		t.Errorf("names:\n got %q\nwant %q", strings.Join(names, "|"), want)
	}
	if len(srv.HostNet) != 1 || srv.HostNet[0] != "adguard" {
		t.Errorf("host network: %q", srv.HostNet)
	}
	ports := map[string]mapPort{}
	for _, s := range srv.Services {
		for _, p := range s.Ports {
			ports[s.Name+" "+p.Text] = p
		}
	}
	for key, href := range map[string]string{
		"photoprism 10.10.10.15:2342": "http://10.10.10.15:2342/", // bound to a service address
		"unifi 10.10.10.5:8443":       "https://10.10.10.5:8443/", // every address: the primary one
		"unifi 3478/udp":              "",                         // UDP: no link
		"gitea 10.10.10.12:2222":      "",                         // SSH: no link
	} {
		p, ok := ports[key]
		if !ok {
			t.Errorf("no port %q among %v", key, ports)
			continue
		}
		if p.Href != href {
			t.Errorf("%s links to %q, want %q", key, p.Href, href)
		}
	}
	for _, s := range srv.Services {
		switch s.Name {
		case "worker", "sidecar":
			t.Errorf("%s publishes nothing of its own and is listed as a service", s.Name)
		case "unifi":
			if strings.Join(s.Shares, ",") != "sidecar" {
				t.Errorf("unifi's network holds %q", s.Shares)
			}
		}
	}
	if len(m.Orphans) != 1 || m.Orphans[0].Host != "nas.example.net" || m.Orphans[0].IPs != "" {
		t.Errorf("names of systems that never reported: %+v", m.Orphans)
	}
}

func TestMapPage(t *testing.T) {
	h := Handler(Options{
		Store: mapStore(t), Policy: model.DefaultPolicy(), Now: func() time.Time { return testNow },
		Version: "test", findings: noFindings, Map: mapOptions(),
	})
	rec := get(t, h, "/map")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	doc := parsePage(t, rec.Body.String())
	for _, want := range []string{
		"ssh admin@10.10.10.5", "ssh -p 2200 admin@10.10.10.5",
		"photos.example.net → 10.10.11.1 · photoprism",
		"on the host's network: adguard",
		"with sidecar in its network",
		"Names of systems that have not reported 1",
	} {
		if !strings.Contains(doc.text, want) {
			t.Errorf("the page does not say %q:\n%s", want, doc.text)
		}
	}
	links := map[string]bool{}
	for _, e := range doc.elements {
		if e.name == "a" {
			links[e.attrs["href"]] = true
		}
	}
	for _, href := range []string{"./map", "./systems/server", "https://photos.example.net/", "http://10.10.10.15:2342/", "https://fw.example.net:10000"} {
		if !links[href] {
			t.Errorf("no link to %q", href)
		}
	}
}

func TestMapLookupIsBounded(t *testing.T) {
	m := mapOptions()
	m.Lookup = func(ctx context.Context, host string) ([]string, error) {
		<-ctx.Done() // a resolver that never answers
		return nil, ctx.Err()
	}
	h := Handler(Options{Store: mapStore(t), Policy: model.DefaultPolicy(), Now: func() time.Time { return testNow }, findings: noFindings, Map: m})
	start := time.Now()
	if rec := get(t, h, "/map"); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if took := time.Since(start); took > lookupTimeout+time.Second {
		t.Errorf("the page took %s with a resolver that never answers", took)
	}
}
