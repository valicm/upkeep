// Package demo fills a store with made-up but realistic data, for "upkeep server -demo" and for
// the dashboard's own tests.
package demo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/valicm/upkeep/internal/model"
	"github.com/valicm/upkeep/internal/report"
	"github.com/valicm/upkeep/internal/store"
)

// Fill puts a small homelab into s: a few Linux hosts, two firewalls and a Home Assistant, with
// every kind of state the dashboard can show. All times are counted back from now, so the demo
// looks the same whenever it runs.
func Fill(ctx context.Context, s store.Store, now time.Time) error {
	for _, sys := range systems(now) {
		if err := sys.Report.Validate(); err != nil {
			return fmt.Errorf("demo report of %s: %w", sys.Report.System.Name, err)
		}
		if err := s.SaveReport(ctx, &sys.Report, sys.ReceivedAt); err != nil {
			return fmt.Errorf("save the demo report of %s: %w", sys.Report.System.Name, err)
		}
	}
	for _, c := range imageChecks(now) {
		if err := s.SaveImageCheck(ctx, c); err != nil {
			return fmt.Errorf("save the demo check of %s: %w", c.Image, err)
		}
	}
	return nil
}

// The versions a demo agent and a demo server claim to be.
const (
	agentAMD64  = "0.1.0 linux/amd64"
	agentARM64  = "0.1.0 linux/arm64"
	serverBuild = "0.1.0 linux/amd64"
)

// The images in use, written once so that containers and checks cannot drift apart.
const (
	imgGitea      = "docker.io/gitea/gitea:1.23.6"
	imgMariaDB114 = "docker.io/library/mariadb:11.4.13"
	imgMariaDB118 = "docker.io/library/mariadb:11.8.9"
	imgPhotoprism = "docker.io/photoprism/photoprism:251130"
	imgUnifi      = "lscr.io/linuxserver/unifi-network-application:10.0.162-ls114"
	imgMongo      = "docker.io/library/mongo:7.0.48"
	imgOllama     = "docker.io/ollama/ollama:latest"
	imgMedimorec  = "localhost/medimorec-server:current"
	imgAdguard    = "docker.io/adguard/adguardhome:latest"
	imgAdguardSyn = "ghcr.io/bakito/adguardhome-sync:v0.8.2"
	imgUptimeKuma = "docker.io/louislam/uptime-kuma:2"
	imgBeszel     = "docker.io/henrygd/beszel:0.21.2"
	imgMailpit    = "docker.io/axllent/mailpit:latest"
	imgRestServer = "docker.io/restic/rest-server:0.14.0"
)

// imgMateria is pinned by digest and has no tag, like the real one.
var imgMateria = "ghcr.io/stryan/materia@" + digest("materia")

// digest makes a well-formed digest out of a word. It is the hash of nothing real, which is
// the point: nobody can mistake it for an image that exists.
func digest(seed string) string {
	sum := sha256.Sum256([]byte("upkeep demo " + seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hours(n float64) time.Duration { return time.Duration(n * float64(time.Hour)) }

// container builds one running Podman container. pulled names the digest it runs; a check with
// another digest for the same tag means the tag was rebuilt since.
func container(now time.Time, name, image, pulled, autoUpdate string, startedHoursAgo float64) report.Container {
	return report.Container{
		Name:       name,
		Image:      image,
		ImageID:    digest("id " + pulled)[len("sha256:"):],
		Digest:     digest(pulled),
		State:      "running",
		StartedAt:  now.Add(-hours(startedHoursAgo)),
		AutoUpdate: autoUpdate,
		Runtime:    "podman",
	}
}

// systems is the homelab. The package names and versions of the Debian hosts are real: they
// come from "apt list --upgradable" in a debian:trixie-20250811-slim container on 2026-11-19.
func systems(now time.Time) []model.SystemState {
	ago := func(h float64) time.Time { return now.Add(-hours(h)) }
	debian := func(name, arch, kernel, agent string) report.System {
		return report.System{
			Name: name, Kind: "linux", OS: "Debian GNU/Linux 13 (trixie)", OSVersion: "13.7",
			Kernel: kernel, Arch: arch, Source: "agent", AgentVersion: agent,
		}
	}
	state := func(r report.Report, receivedHoursAgo float64) model.SystemState {
		r.Schema = report.Schema
		r.Sent = ago(receivedHoursAgo).Add(-2 * time.Second)
		return model.SystemState{Report: r, ReceivedAt: ago(receivedHoursAgo)}
	}

	// server: security updates, a reboot that waits, containers with a newer patch, minor and
	// major, one failed backup and one that is fine.
	server := state(report.Report{
		System: debian("server", "amd64", "6.12.107+deb13-amd64", agentAMD64),
		Packages: &report.Packages{
			Manager: "apt", Pending: 12, Security: 3,
			Items: []report.PackageUpdate{
				{Name: "base-files", Installed: "13.8", Candidate: "13.8+deb13u7"},
				{Name: "bash", Installed: "5.2.37-2+b5", Candidate: "5.2.37-2+b10"},
				{Name: "libc-bin", Installed: "2.41-12", Candidate: "2.41-12+deb13u4"},
				{Name: "libc6", Installed: "2.41-12", Candidate: "2.41-12+deb13u4"},
				{Name: "liblzma5", Installed: "5.8.1-1", Candidate: "5.8.1-1+deb13u2", Security: true},
				{Name: "libsqlite3-0", Installed: "3.46.1-7", Candidate: "3.46.1-7+deb13u2"},
				{Name: "libssl3t64", Installed: "3.5.1-1", Candidate: "3.5.7-1~deb13u3", Security: true},
				{Name: "libsystemd0", Installed: "257.7-1", Candidate: "257.13-1~deb13u1"},
				{Name: "libudev1", Installed: "257.7-1", Candidate: "257.13-1~deb13u1"},
				{Name: "openssl-provider-legacy", Installed: "3.5.1-1", Candidate: "3.5.7-1~deb13u3", Security: true},
				{Name: "sed", Installed: "4.9-2", Candidate: "4.9-2+deb13u1"},
				{Name: "tzdata", Installed: "2025b-4", Candidate: "2026f-0+deb13u1"},
			},
			RebootRequired: true,
			RebootReason:   "kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed",
			ListsUpdated:   ago(5),
		},
		Containers: []report.Container{
			container(now, "gitea", imgGitea, "gitea", "", 21*24),
			container(now, "gitea-db", imgMariaDB114, "mariadb 11.4", "", 21*24),
			container(now, "photoprism", imgPhotoprism, "photoprism", "", 9*24),
			container(now, "photoprism-db", imgMariaDB118, "mariadb 11.8", "", 9*24),
			container(now, "unifi", imgUnifi, "unifi", "", 6*24),
			container(now, "unifi-db", imgMongo, "mongo", "", 6*24),
			container(now, "ollama", imgOllama, "ollama before the rebuild", "registry", 4*24),
			container(now, "medimorec", imgMedimorec, "medimorec", "", 30),
			container(now, "materia", imgMateria, "materia", "", 12*24),
		},
		Backups: []report.Backup{
			{
				Name: "restic-backup", Kind: "restic",
				LastSuccess: ago(53), LastRun: ago(5), LastResult: "failed",
				Detail: "exit-code 3",
			},
			{
				Name: "mariadb-dump", Kind: "systemd",
				LastSuccess: ago(6), LastRun: ago(6), LastResult: "ok",
			},
		},
	}, 4.0/60)

	// ops01: plain updates only, a tag that was rebuilt and pulls itself, one that was rebuilt
	// and does not, an image nobody has checked yet, and a backup that is late.
	ops01 := state(report.Report{
		System: debian("ops01", "arm64", "6.12.117+deb13-arm64", agentARM64),
		Packages: &report.Packages{
			Manager: "apt", Pending: 4,
			Items: []report.PackageUpdate{
				{Name: "base-files", Installed: "13.8", Candidate: "13.8+deb13u7"},
				{Name: "gzip", Installed: "1.13-1", Candidate: "1.13-1+deb13u1"},
				{Name: "sqv", Installed: "1.3.0-3", Candidate: "1.3.0-3+b2"},
				{Name: "tzdata", Installed: "2025b-4", Candidate: "2026f-0+deb13u1"},
			},
			ListsUpdated: ago(3),
		},
		Containers: []report.Container{
			container(now, "adguard", imgAdguard, "adguardhome before the rebuild", "registry", 8*24),
			container(now, "adguardhome-sync", imgAdguardSyn, "adguardhome-sync", "", 8*24),
			container(now, "uptime-kuma", imgUptimeKuma, "uptime-kuma before the rebuild", "", 15*24),
			container(now, "beszel", imgBeszel, "beszel", "", 3*24),
			container(now, "mailpit", imgMailpit, "mailpit", "registry", 26),
			container(now, "materia", imgMateria, "materia", "", 12*24),
		},
		Backups: []report.Backup{{
			Name: "restic-backup", Kind: "restic",
			LastSuccess: ago(40), LastRun: ago(40), LastResult: "ok",
			Detail: "snapshot 7c1e09ab, 3.1 GiB",
		}},
	}, 2.0/60)

	// dns02: went silent three days ago, and its backup never ran.
	dns02 := state(report.Report{
		System:   debian("dns02", "arm64", "6.12.117+deb13-arm64", agentARM64),
		Packages: &report.Packages{Manager: "apt", ListsUpdated: ago(80)},
		Containers: []report.Container{
			container(now, "adguard", imgAdguard, "adguardhome before the rebuild", "registry", 30*24),
		},
		Backups: []report.Backup{{
			Name: "restic-backup", Kind: "restic", LastResult: "unknown",
			Detail: "restic-backup.timer has not fired yet",
		}},
	}, 74)

	// storage: a collector that could not do its job, a registry that would not answer, and a
	// backup that is running right now.
	storage := state(report.Report{
		System: debian("storage", "arm64", "6.12.117+deb13-arm64", agentARM64),
		Packages: &report.Packages{
			Manager: "apt", Pending: 3, Security: 1,
			Items: []report.PackageUpdate{
				{Name: "dpkg", Installed: "1.22.21", Candidate: "1.22.22"},
				{Name: "libpcre2-8-0", Installed: "10.45-1", Candidate: "10.46-1~deb13u3", Security: true},
				{Name: "perl-base", Installed: "5.40.1-6", Candidate: "5.40.1-6+deb13u1"},
			},
			ListsUpdated: ago(4 * 24),
		},
		Containers: []report.Container{
			container(now, "restic-server", imgRestServer, "rest-server", "", 40*24),
		},
		Backups: []report.Backup{{
			Name: "restic-backup", Kind: "restic",
			LastSuccess: ago(24), LastRun: ago(10.0 / 60), LastResult: "running",
			Detail: "started by restic-backup.timer",
		}},
		Errors: []report.Problem{{
			Collector: "ospkg",
			Message:   "apt-get update: exit status 100: Temporary failure resolving 'deb.debian.org'; the counts come from lists that are 4 days old",
		}},
	}, 7.0/60)

	// opnsense: asked through its API. A firmware update is out.
	opnsense := state(report.Report{
		System: report.System{
			Name: "opnsense", Kind: "opnsense", OS: "OPNsense", OSVersion: "26.10",
			Kernel: "FreeBSD 14.3-RELEASE-p7", Arch: "amd64", Source: "connector", AgentVersion: serverBuild,
		},
		Software: []report.Software{
			{
				Name: "OPNsense", Kind: "firmware", Installed: "26.10", Latest: "26.10.1", UpdateAvailable: true,
				URL: "https://docs.opnsense.org/releases/BE_26.10.html", Detail: "41 packages, needs a reboot",
			},
			{Name: "os-acme-client", Kind: "plugin", Installed: "4.12", Latest: "4.12"},
			{Name: "os-ddclient", Kind: "plugin", Installed: "1.29", Latest: "1.29"},
		},
	}, 11.0/60)

	// opnsense02: the standby firewall got the update first. Nothing to do.
	opnsense02 := state(report.Report{
		System: report.System{
			Name: "opnsense02", Kind: "opnsense", OS: "OPNsense", OSVersion: "26.10.1",
			Kernel: "FreeBSD 14.3-RELEASE-p7", Arch: "amd64", Source: "connector", AgentVersion: serverBuild,
		},
		Software: []report.Software{
			{
				Name: "OPNsense", Kind: "firmware", Installed: "26.10.1", Latest: "26.10.1",
				URL: "https://docs.opnsense.org/releases/BE_26.10.html",
			},
			{Name: "os-acme-client", Kind: "plugin", Installed: "4.12", Latest: "4.12"},
			{Name: "os-ddclient", Kind: "plugin", Installed: "1.29", Latest: "1.29"},
		},
	}, 11.0/60)

	// homeassistant: asked through its API. Core and one app have an update, the backup is fine.
	homeassistant := state(report.Report{
		System: report.System{
			Name: "homeassistant", Kind: "homeassistant", OS: "Home Assistant OS", OSVersion: "18.5",
			Arch: "arm64", Source: "connector", AgentVersion: serverBuild,
		},
		Software: []report.Software{
			{
				Name: "Home Assistant Core", Kind: "core", Installed: "2026.11.1", Latest: "2026.11.2", UpdateAvailable: true,
				URL: "https://www.home-assistant.io/latest-release-notes/",
			},
			{Name: "Home Assistant Operating System", Kind: "os", Installed: "18.5", Latest: "18.5"},
			{Name: "Home Assistant Supervisor", Kind: "supervisor", Installed: "2026.11.0", Latest: "2026.11.0"},
			{
				Name: "Zigbee2MQTT", Kind: "app", Installed: "2.6.3-1", Latest: "2.7.0-1", UpdateAvailable: true,
				URL: "https://github.com/zigbee2mqtt/hassio-zigbee2mqtt/releases",
			},
			{Name: "Mosquitto broker", Kind: "app", Installed: "6.5.2", Latest: "6.5.2"},
			{Name: "ESPHome Device Builder", Kind: "app", Installed: "2026.10.3", Latest: "2026.10.3"},
		},
		Backups: []report.Backup{{
			Name: "automatic backup", Kind: "homeassistant",
			LastSuccess: ago(9), LastRun: ago(9), LastResult: "ok", MaxAgeHours: 48,
			Detail: "Home Assistant 2026.11.1, 412 MiB",
		}},
	}, 9.0/60)

	return []model.SystemState{server, ops01, dns02, storage, opnsense, opnsense02, homeassistant}
}

// imageChecks is what the server stores after asking the registries about the images above.
// The newer tags are real: they are the newest ones the registries listed on 2026-11-19.
func imageChecks(now time.Time) []model.ImageCheck {
	at := now.Add(-35 * time.Minute)
	// same is a check that found the tag where the container pulled it.
	same := func(image, tag, pulled string) model.ImageCheck {
		return model.ImageCheck{Image: image, Tag: tag, TagDigest: digest(pulled), CheckedAt: at}
	}
	with := func(c model.ImageCheck, patch, minor, major string) model.ImageCheck {
		c.NewerPatch, c.NewerMinor, c.NewerMajor = patch, minor, major
		return c
	}
	return []model.ImageCheck{
		with(same(imgGitea, "1.23.6", "gitea"), "1.23.8", "1.27.3", ""),
		with(same(imgMariaDB114, "11.4.13", "mariadb 11.4"), "", "11.8.9", "13.0.2"),
		with(same(imgMariaDB118, "11.8.9", "mariadb 11.8"), "", "", "13.0.2"),
		same(imgPhotoprism, "251130", "photoprism"),
		with(same(imgUnifi, "10.0.162-ls114", "unifi"), "", "10.6.109-ls155", ""),
		with(same(imgMongo, "7.0.48", "mongo"), "", "", "9.0.8"),
		// Rebuilt: the tag points at another image than the one the containers run.
		same(imgOllama, "latest", "ollama after the rebuild"),
		same(imgAdguard, "latest", "adguardhome after the rebuild"),
		same(imgUptimeKuma, "2", "uptime-kuma after the rebuild"),
		same(imgBeszel, "0.21.2", "beszel"),
		same(imgMailpit, "latest", "mailpit"),
		// The registry would not answer: the words are the registry client's own for a 429.
		{
			Image: imgRestServer, Tag: "0.14.0", CheckedAt: at,
			Error: "asking what docker.io/restic/rest-server:0.14.0 points at: too many requests, the registry asks to slow down (HTTP 429 TOOMANYREQUESTS)",
		},
		// Three images have no check, as on a real server: imgMedimorec is local and imgMateria
		// is pinned by digest, so no registry is ever asked about them, and imgAdguardSyn was
		// just not asked yet.
	}
}
