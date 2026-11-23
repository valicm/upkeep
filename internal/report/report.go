// Package report is the one format every source uses to say what it found on one system: an
// agent running on a machine pushes it, and a connector that polls an appliance's API builds the
// same thing. It is the contract between the parts of upkeep, so fields are only ever added.
package report

import (
	"errors"
	"strings"
	"time"
)

// Schema is the format's version. A server accepts reports with this or an older schema.
const Schema = 1

// Report is everything one source knows about one system at one moment. A nil or empty part
// means "this source does not look at that", never "nothing pending": a collector that looked
// and failed says so in Errors.
type Report struct {
	Schema     int         `json:"schema"`
	System     System      `json:"system"`
	Sent       time.Time   `json:"sent"`
	Packages   *Packages   `json:"packages,omitempty"`
	Software   []Software  `json:"software,omitempty"`
	Containers []Container `json:"containers,omitempty"`
	Backups    []Backup    `json:"backups,omitempty"`
	Errors     []Problem   `json:"errors,omitempty"`
}

// System identifies what the report is about. Name is the key: a later report with the same
// name replaces the earlier one.
type System struct {
	Name         string `json:"name"`                    // "server", "opnsense02", "homeassistant"
	Kind         string `json:"kind"`                    // "linux", "freebsd", "opnsense", "homeassistant"
	OS           string `json:"os,omitempty"`            // "Debian GNU/Linux 13 (trixie)"
	OSVersion    string `json:"os_version,omitempty"`    // "13.7", "26.10.1", "18.5"
	Kernel       string `json:"kernel,omitempty"`        // running kernel release
	Arch         string `json:"arch,omitempty"`          // "amd64", "arm64"
	Source       string `json:"source"`                  // "agent" or "connector"
	AgentVersion string `json:"agent_version,omitempty"` // version of the upkeep binary that built this

	Network *Network `json:"network,omitempty"` // how the system is reached; agents only
}

// Network is how a system is reached on its own network: what the dashboard's map shows.
type Network struct {
	Hostname  string    `json:"hostname,omitempty"`  // the name the system gives itself
	Primary   string    `json:"primary,omitempty"`   // the address it reaches the upkeep server from
	Addresses []Address `json:"addresses,omitempty"` // every address of its own interfaces
	SSHPorts  []int     `json:"ssh_ports,omitempty"` // where an SSH server listens; none when none does
}

// Address is one address of one interface.
type Address struct {
	Interface string `json:"interface"` // "enp73s0", "eth0"
	IP        string `json:"ip"`        // "10.10.10.5", "fd00::5"
	Prefix    int    `json:"prefix"`    // 24
}

// Packages is the state of the system's package manager.
type Packages struct {
	Manager        string          `json:"manager"`                 // "apt", "dnf", "pkg", "apk"
	Pending        int             `json:"pending"`                 // packages with a newer version available
	Security       int             `json:"security"`                // how many of those are security updates, when known
	Items          []PackageUpdate `json:"items,omitempty"`         // the pending packages, at most MaxItems
	RebootRequired bool            `json:"reboot_required"`         // the system asks for a reboot
	RebootReason   string          `json:"reboot_reason,omitempty"` // "linux-image-6.12.117", "kernel 6.12.107 running, 6.12.117 installed"
	ListsUpdated   time.Time       `json:"lists_updated,omitzero"`  // when the package lists were last refreshed
	// KeptBack are packages that have a newer version which an upgrade would not install: held
	// by the administrator, phased by the distribution, or kept back because their dependencies
	// cannot be met. They are not counted in Pending. At most MaxItems.
	KeptBack []PackageUpdate `json:"kept_back,omitempty"`
}

// MaxItems caps the package list in one report.
const MaxItems = 300

// PackageUpdate is one package that has a newer version.
type PackageUpdate struct {
	Name      string `json:"name"`
	Installed string `json:"installed,omitempty"`
	Candidate string `json:"candidate,omitempty"`
	Security  bool   `json:"security,omitempty"`
	Reason    string `json:"reason,omitempty"` // only in KeptBack: "held", "phased" or "kept back"
}

// Software is one named thing with its own version outside the package manager: an appliance's
// firmware, Home Assistant's core, its operating system, one of its apps, a plugin.
type Software struct {
	Name            string `json:"name"`           // "OPNsense", "Home Assistant Core", "Zigbee2MQTT"
	Kind            string `json:"kind,omitempty"` // "firmware", "core", "os", "supervisor", "app", "plugin", "integration"
	Installed       string `json:"installed,omitempty"`
	Latest          string `json:"latest,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	URL             string `json:"url,omitempty"`    // release notes
	Detail          string `json:"detail,omitempty"` // "needs a reboot", "12 packages"
}

// Container is one running container. The server compares Image and Digest with the registry:
// the agent itself never talks to a registry.
type Container struct {
	Name    string `json:"name"`
	Image   string `json:"image"` // as configured: "docker.io/gitea/gitea:1.23.6"
	ImageID string `json:"image_id,omitempty"`
	Digest  string `json:"digest,omitempty"` // "sha256:..." the image was pulled as, when known
	// Digests are all the digests the runtime knows the local image by in this repository. An
	// image for several architectures has two, the one of the whole set and the one of this
	// machine's variant, and more after it was pulled again. The tag in the registry was only
	// rebuilt when it points at none of them.
	Digests    []string  `json:"digests,omitempty"`
	State      string    `json:"state,omitempty"` // "running", "exited"
	StartedAt  time.Time `json:"started_at,omitzero"`
	AutoUpdate string    `json:"auto_update,omitempty"` // Podman's io.containers.autoupdate label, e.g. "registry"
	Runtime    string    `json:"runtime,omitempty"`     // "podman", "docker"

	// What the container offers on the host's network: Network is "host" when it shares the
	// host's network, and then Ports is empty, because every port it opens is the host's.
	Network string `json:"network,omitempty"`
	Ports   []Port `json:"ports,omitempty"`
}

// Port is one port a container publishes on the host.
type Port struct {
	HostIP   string `json:"host_ip,omitempty"` // empty: every address of the host
	HostPort int    `json:"host_port"`
	Port     int    `json:"port"`     // inside the container
	Protocol string `json:"protocol"` // "tcp", "udp", "sctp"
}

// Backup is one backup job as seen from the reporting system.
type Backup struct {
	Name        string    `json:"name"`                  // "restic-backup", "homeassistant automatic backup"
	Kind        string    `json:"kind,omitempty"`        // "restic", "systemd", "file", "homeassistant"
	LastSuccess time.Time `json:"last_success,omitzero"` // zero when it never succeeded as far as known
	LastRun     time.Time `json:"last_run,omitzero"`
	LastResult  string    `json:"last_result,omitempty"`   // "ok", "failed", "running", "unknown"
	MaxAgeHours int       `json:"max_age_hours,omitempty"` // older than this is stale; 0 means the server's default
	Detail      string    `json:"detail,omitempty"`        // "exit-code 3", "snapshot 1a2b3c4d, 41 GiB"
}

// Problem is a collector that could not do its job. It keeps "no data" apart from "all good".
type Problem struct {
	Collector string `json:"collector"`
	Message   string `json:"message"`
}

// Validate checks what a server needs before it stores a report.
func (r *Report) Validate() error {
	name := strings.TrimSpace(r.System.Name)
	switch {
	case r.Schema < 1 || r.Schema > Schema:
		return errors.New("unknown schema")
	case name == "" || len(name) > 100 || strings.ContainsAny(name, "/\\\x00\n\r"):
		return errors.New("system name is missing or not usable")
	case name == "." || name == "..":
		// The name is part of the system's address on the dashboard, and no browser asks for "..".
		return errors.New("system name is not usable")
	case r.System.Source != "agent" && r.System.Source != "connector":
		return errors.New("source must be agent or connector")
	}
	return nil
}
