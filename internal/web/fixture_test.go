package web

import (
	"time"

	"github.com/valicm/upkeep/internal/model"
)

// demoFindings is what model.Findings says about the demo homelab at testNow with the default
// policy. It was captured from model.Findings itself on 2026-11-19 and is kept here as data:
// the dashboard's tests must not start to fail because the wording of a finding changes in
// another package. TestRealFindings runs the pages against the real function as well.
func demoFindings([]model.SystemState, map[string]model.ImageCheck, time.Time, model.Policy) []model.Finding {
	return []model.Finding{
		{System: "dns02", Category: model.CategorySource, Severity: model.Crit, Title: "no report since 2026-11-16 08:00 UTC", Detail: "silent for 3 days; the agent should report at least every 2 hours"},
		{System: "server", Category: model.CategoryBackup, Severity: model.Crit, Title: "backup restic-backup failed", Detail: "last run 2026-11-19 05:00 UTC; exit-code 3; last success 2026-11-17 05:00 UTC"},
		{System: "dns02", Category: model.CategoryBackup, Severity: model.Warn, Title: "backup restic-backup never succeeded", Detail: "restic-backup.timer has not fired yet"},
		{System: "dns02", Category: model.CategoryOS, Severity: model.Warn, Title: "package lists not refreshed since 2026-11-16", Detail: "3 days ago (apt); newer updates may exist that are not counted here"},
		{System: "ops01", Category: model.CategoryBackup, Severity: model.Warn, Title: "backup restic-backup last succeeded 2026-11-17", Detail: "40 hours ago, at 18:00 UTC; allowed age is 26 hours"},
		{System: "server", Category: model.CategoryReboot, Severity: model.Warn, Title: "reboot required", Detail: "kernel 6.12.107+deb13-amd64 running, 6.12.117+deb13-amd64 installed"},
		{System: "server", Category: model.CategoryOS, Severity: model.Warn, Title: "12 package updates, 3 security", Detail: "security: liblzma5, libssl3t64, openssl-provider-legacy; also base-files, bash, libc-bin, libc6, libsqlite3-0 and 4 more"},
		{System: "storage", Category: model.CategorySource, Severity: model.Warn, Title: "collector ospkg failed", Detail: "apt-get update: exit status 100: Temporary failure resolving 'deb.debian.org'; the counts come from lists that are 4 days old"},
		{System: "storage", Category: model.CategoryOS, Severity: model.Warn, Title: "3 package updates, 1 security", Detail: "security: libpcre2-8-0; also dpkg, perl-base"},
		{System: "storage", Category: model.CategoryOS, Severity: model.Warn, Title: "package lists not refreshed since 2026-11-15", Detail: "4 days ago (apt); newer updates may exist that are not counted here"},
		{System: "dns02", Category: model.CategoryContainer, Severity: model.Info, Title: "adguard: tag latest was rebuilt", Detail: "docker.io/adguard/adguardhome:latest is now sha256:d4539264c634, the container runs sha256:c168ef32a281; it updates itself (auto-update registry)"},
		{System: "homeassistant", Category: model.CategorySoftware, Severity: model.Info, Title: "Home Assistant Core 2026.11.2 available", Detail: "installed 2026.11.1; https://www.home-assistant.io/latest-release-notes/"},
		{System: "homeassistant", Category: model.CategorySoftware, Severity: model.Info, Title: "Zigbee2MQTT 2.7.0-1 available", Detail: "installed 2.6.3-1; https://github.com/zigbee2mqtt/hassio-zigbee2mqtt/releases"},
		{System: "opnsense", Category: model.CategorySoftware, Severity: model.Info, Title: "OPNsense 26.10.1 available", Detail: "installed 26.10; 41 packages, needs a reboot; https://docs.opnsense.org/releases/BE_26.10.html"},
		{System: "ops01", Category: model.CategoryOS, Severity: model.Info, Title: "4 package updates", Detail: "base-files, gzip, sqv, tzdata"},
		{System: "ops01", Category: model.CategoryContainer, Severity: model.Info, Title: "adguard: tag latest was rebuilt", Detail: "docker.io/adguard/adguardhome:latest is now sha256:d4539264c634, the container runs sha256:c168ef32a281; it updates itself (auto-update registry)"},
		{System: "ops01", Category: model.CategoryContainer, Severity: model.Info, Title: "uptime-kuma: tag 2 was rebuilt", Detail: "docker.io/louislam/uptime-kuma:2 is now sha256:764faee187aa, the container runs sha256:cb58dc35bd97; pull the image and restart the container"},
		{System: "server", Category: model.CategoryContainer, Severity: model.Info, Title: "gitea-db: 11.8.9 available", Detail: "minor update of docker.io/library/mariadb:11.4.13; also 13.0.2 (major)"},
		{System: "server", Category: model.CategoryContainer, Severity: model.Info, Title: "gitea: 1.23.8 available", Detail: "patch update of docker.io/gitea/gitea:1.23.6; also 1.27.3 (minor)"},
		{System: "server", Category: model.CategoryContainer, Severity: model.Info, Title: "ollama: tag latest was rebuilt", Detail: "docker.io/ollama/ollama:latest is now sha256:9e27becef7a9, the container runs sha256:f2ebe3be498f; it updates itself (auto-update registry)"},
		{System: "server", Category: model.CategoryContainer, Severity: model.Info, Title: "photoprism-db: 13.0.2 available", Detail: "major update of docker.io/library/mariadb:11.8.9"},
		{System: "server", Category: model.CategoryContainer, Severity: model.Info, Title: "unifi-db: 9.0.8 available", Detail: "major update of docker.io/library/mongo:7.0.48"},
		{System: "server", Category: model.CategoryContainer, Severity: model.Info, Title: "unifi: 10.6.109-ls155 available", Detail: "minor update of lscr.io/linuxserver/unifi-network-application:10.0.162-ls114"},
		{System: "storage", Category: model.CategoryContainer, Severity: model.Info, Title: "1 image could not be checked", Detail: "docker.io/restic/rest-server:0.14.0: asking what docker.io/restic/rest-server:0.14.0 points at: too many requests, the registry asks to slow down (HTTP 429 TOOMANYREQUESTS)"},
	}
}
