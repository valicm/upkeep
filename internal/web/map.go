package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/valicm/upkeep/internal/report"
)

// Map is what the map page shows beside what the systems report about themselves.
type Map struct {
	SSHUser    string         // the user in the SSH lines; empty: "ssh <address>"
	Names      []MapName      // names that lead to the systems, as through a reverse proxy
	Appliances []MapAppliance // systems the server asks itself: their URL is their address
	// Lookup resolves a host name for the page. nil: the system's resolver.
	Lookup func(ctx context.Context, host string) ([]string, error)
}

// MapName is one name and what it leads to.
type MapName struct {
	URL    string // "https://photos.example.net/"
	System string // the system it leads to
	Port   int    // the port on that system it leads to; 0 when it is the system as a whole
}

// MapAppliance is a system the server polls over its API.
type MapAppliance struct {
	Name string
	URL  string
}

// lookupTimeout bounds the resolving of every name on one map page, all of them together.
const lookupTimeout = 2 * time.Second

// Ports that do not speak HTTP get no link. A guess: a link that leads nowhere is harmless.
var notWeb = map[int]bool{
	22: true, 25: true, 53: true, 110: true, 143: true, 465: true, 587: true, 993: true, 995: true,
	1025: true, 1883: true, 2222: true, 3306: true, 3478: true, 3493: true, 5432: true,
	6379: true, 8883: true, 27017: true,
}

type mapPage struct {
	page
	Systems []mapSystem
	Orphans []mapName // names whose system has not reported
	SSHUser string
}

type mapSystem struct {
	Name      string
	Href      string
	About     string // "Debian GNU/Linux 13 (trixie)", "OPNsense 26.10.1"
	Primary   string
	PrimaryOf string // "/24 enp73s0": the primary address's prefix and interface, when known
	Others    []mapAddr
	SSH       []string
	Names     []mapName
	Services  []mapService
	HostNet   []string // containers on the host's network
	Appliance string   // the URL the server polls
}

type mapAddr struct {
	IP        string
	Prefix    int
	Interface string
}

type mapName struct {
	Host    string // "photos.example.net"
	URL     string
	IPs     string // what the name resolves to, "" when it does not
	Service string // the container on the port it leads to
	Port    int
	System  string
}

type mapService struct {
	Name   string
	Ports  []mapPort
	Shares []string // the containers that live in its network
}

type mapPort struct {
	Text string // "10.10.10.15:2324", "53/udp"
	Href string
}

func (d *dashboard) mapView(w http.ResponseWriter, r *http.Request) {
	snap := d.loadOrFail(w, r)
	if snap == nil {
		return
	}
	p := d.page(r, snap.now, "map", "Map")
	m := d.opts.Map
	lookup := m.Lookup
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	ctx, cancel := context.WithTimeout(r.Context(), lookupTimeout)
	defer cancel()
	d.render(w, r, http.StatusOK, "map", buildMap(ctx, snap, p, m, lookup))
}

func buildMap(ctx context.Context, snap *snapshot, p page, m Map, lookup func(context.Context, string) ([]string, error)) mapPage {
	out := mapPage{page: p, SSHUser: m.SSHUser}

	// Every name is resolved at once: the page waits for the slowest, not for their sum.
	var toResolve []string
	seen := map[string]bool{}
	for _, raw := range mapURLs(m) {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || net.ParseIP(u.Hostname()) != nil || seen[u.Hostname()] {
			continue
		}
		seen[u.Hostname()] = true
		toResolve = append(toResolve, u.Hostname())
	}
	hosts := map[string][]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range toResolve {
		wg.Go(func() {
			ips, err := lookup(ctx, h)
			if err != nil {
				return
			}
			// A loopback answer describes the server's own /etc/hosts, as Debian's 127.0.1.1
			// line for its own name: no one reading the page reaches anything there.
			ips = slices.DeleteFunc(ips, func(ip string) bool {
				a := net.ParseIP(ip)
				return a == nil || a.IsLoopback()
			})
			if len(ips) == 0 {
				return
			}
			sort.Strings(ips)
			mu.Lock()
			hosts[h] = ips
			mu.Unlock()
		})
	}
	wg.Wait()
	resolved := func(host string) string {
		if net.ParseIP(host) != nil {
			return ""
		}
		return strings.Join(hosts[host], ", ")
	}

	appliance := map[string]string{}
	for _, a := range m.Appliances {
		appliance[a.Name] = a.URL
	}
	names := map[string][]mapName{}
	for _, n := range m.Names {
		u, err := url.Parse(n.URL)
		if err != nil || u.Host == "" {
			continue
		}
		names[n.System] = append(names[n.System], mapName{
			Host: u.Host, URL: n.URL, IPs: resolved(u.Hostname()), Port: n.Port, System: n.System,
		})
	}

	known := map[string]bool{}
	for _, st := range snap.states {
		rep := st.Report
		known[rep.System.Name] = true
		s := mapSystem{
			Name:  rep.System.Name,
			Href:  systemHref(p.Root, rep.System.Name),
			About: strings.TrimSpace(rep.System.OS + " " + osVersionUnlessNamed(rep.System)),
		}
		if nw := rep.System.Network; nw != nil {
			s.Primary = nw.Primary
			for _, a := range nw.Addresses {
				if a.IP == nw.Primary {
					s.PrimaryOf = fmt.Sprintf("/%d %s", a.Prefix, a.Interface)
					continue
				}
				s.Others = append(s.Others, mapAddr{IP: a.IP, Prefix: a.Prefix, Interface: a.Interface})
			}
			if s.Primary == "" && len(s.Others) > 0 {
				first := s.Others[0]
				s.Primary, s.PrimaryOf, s.Others = first.IP, fmt.Sprintf("/%d %s", first.Prefix, first.Interface), s.Others[1:]
			}
			if s.Primary != "" {
				for _, port := range nw.SSHPorts {
					s.SSH = append(s.SSH, sshLine(m.SSHUser, s.Primary, port))
				}
			}
		}
		if u, ok := appliance[rep.System.Name]; ok {
			s.Appliance = u
			if pu, err := url.Parse(u); err == nil && s.Primary == "" {
				if net.ParseIP(pu.Hostname()) != nil {
					s.Primary = pu.Hostname()
				} else if ips := resolved(pu.Hostname()); ips != "" {
					s.Primary = ips
				}
			}
		}
		byPort := map[int]string{}
		guests := map[string][]string{} // owner: the containers in its network
		for _, c := range rep.Containers {
			if c.Network == "host" {
				s.HostNet = append(s.HostNet, c.Name)
				continue
			}
			if owner, ok := strings.CutPrefix(c.Network, "container:"); ok {
				guests[owner] = append(guests[owner], c.Name)
				continue
			}
			if len(c.Ports) == 0 {
				continue
			}
			svc := mapService{Name: c.Name}
			for _, pt := range c.Ports {
				if _, taken := byPort[pt.HostPort]; !taken {
					byPort[pt.HostPort] = c.Name
				}
				svc.Ports = append(svc.Ports, portView(pt, s.Primary))
			}
			s.Services = append(s.Services, svc)
		}
		for i := range s.Services {
			s.Services[i].Shares = guests[s.Services[i].Name]
			sort.Strings(s.Services[i].Shares)
		}
		sort.Strings(s.HostNet)
		sort.SliceStable(s.Services, func(i, j int) bool { return s.Services[i].Name < s.Services[j].Name })
		for _, n := range names[rep.System.Name] {
			if n.Port > 0 {
				n.Service = byPort[n.Port]
			}
			s.Names = append(s.Names, n)
		}
		out.Systems = append(out.Systems, s)
	}
	sort.SliceStable(out.Systems, func(i, j int) bool { return out.Systems[i].Name < out.Systems[j].Name })

	var orphanSystems []string
	for sys := range names {
		if !known[sys] {
			orphanSystems = append(orphanSystems, sys)
		}
	}
	sort.Strings(orphanSystems)
	for _, sys := range orphanSystems {
		out.Orphans = append(out.Orphans, names[sys]...)
	}
	return out
}

// mapURLs is every URL the page may show a name of.
func mapURLs(m Map) []string {
	var out []string
	for _, n := range m.Names {
		out = append(out, n.URL)
	}
	for _, a := range m.Appliances {
		out = append(out, a.URL)
	}
	return out
}

// osVersionUnlessNamed adds the version when the OS name does not carry it already: Debian's
// PRETTY_NAME says "13", the version says "13.7".
func osVersionUnlessNamed(s report.System) string {
	if s.OSVersion == "" || strings.Contains(s.OS, s.OSVersion) {
		return ""
	}
	return s.OSVersion
}

func sshLine(user, host string, port int) string {
	target := host
	if user != "" {
		target = user + "@" + target
	}
	if port != 22 {
		return "ssh -p " + strconv.Itoa(port) + " " + target
	}
	return "ssh " + target
}

// portView shows one published port, and links it when it may be a web page.
func portView(pt report.Port, primary string) mapPort {
	host := pt.HostIP
	if host == "" {
		host = primary
	}
	if pt.Protocol != "tcp" || host == "" {
		text := strconv.Itoa(pt.HostPort)
		if pt.HostIP != "" {
			text = net.JoinHostPort(pt.HostIP, text)
		}
		if pt.Protocol != "tcp" {
			text += "/" + pt.Protocol
		}
		return mapPort{Text: text}
	}
	hostport := net.JoinHostPort(host, strconv.Itoa(pt.HostPort))
	v := mapPort{Text: hostport}
	if !notWeb[pt.HostPort] && !notWeb[pt.Port] {
		scheme := "http"
		if pt.HostPort == 443 || pt.HostPort == 8443 || pt.Port == 443 || pt.Port == 8443 {
			scheme = "https"
		}
		v.Href = fmt.Sprintf("%s://%s/", scheme, hostport)
	}
	return v
}
