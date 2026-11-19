# upkeep

One page that says what needs attention on every machine of a small network: pending
operating system packages and security updates, a reboot that waits, container images with
something newer in the registry, firmware and app updates of appliances, and backups that
failed or did not run.

It is one static binary with two roles:

- `upkeep agent` runs on a machine and pushes a report to the server every 15 minutes. It
  only looks: it needs no root, refreshes nothing and changes nothing.
- `upkeep server` stores the latest report of every system, asks appliances through their own
  APIs (OPNsense, Home Assistant), asks the container registries about the images in use,
  serves the dashboard and sends a digest mail.

So a system gets onto the dashboard in one of two ways, and both give the same rows: an
**agent** installed on it, or a **connector** in the server's configuration that asks the
system's API with nothing installed there. An agent can also run a connector locally, for an
appliance the server cannot reach.

## See it first

```sh
scripts/build.sh                        # needs Go 1.27; puts the binaries into dist/
dist/upkeep-linux-amd64 server -demo    # made-up systems on http://127.0.0.1:8484
```

## From nothing to a server and one agent

The binaries are `dist/upkeep-linux-amd64`, `-linux-arm64`, `-linux-armv7` and
`-freebsd-amd64`. Copy the one for the machine to `/usr/local/bin/upkeep`.

**The server**, on the machine that is to show the dashboard:

```sh
mkdir -p /etc/upkeep
od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > /etc/upkeep/token    # the agents' token
chmod 0640 /etc/upkeep/token
cat > /etc/upkeep/server.toml <<'END'
listen = "0.0.0.0:8484"
token_file = "/etc/upkeep/token"
END
upkeep server
```

The dashboard is at `http://<server>:8484/`. It keeps its data in `/var/lib/upkeep`
(`data_dir`). To run it for good, use the container: [as a Podman service](#the-server-under-podman).

**One agent**, on any machine, with the same token in a file:

```sh
upkeep agent -print      # what this machine would report; needs no setup and sends nothing
UPKEEP_SERVER=http://<server>:8484 UPKEEP_TOKEN_FILE=/etc/upkeep/token upkeep agent -once
```

`-once` sends one report and says `report sent: ...`; its exit status tells whether the server
took it. Without `-once` the agent keeps reporting. To run it for good:
[as a systemd service](deploy/systemd/README.md).

## What each collector needs

The agent runs these on every report. Each can be switched off in `agent.toml`; one that
fails shows on the dashboard as a problem of that system, it does not hide.

| Collector | What it reports | What it reads or runs | What it needs |
|---|---|---|---|
| host | operating system, version, kernel, architecture | `/etc/os-release`, `/etc/debian_version`, `/proc/sys/kernel/osrelease` (`uname -r` on FreeBSD) | nothing |
| packages (apt) | pending upgrades, which are security updates, held and kept-back packages, reboot flag, age of the lists | `apt-get -s dist-upgrade` (a simulation, no lock), `/var/lib/apt/lists`, `/run/reboot-required` | any user; the machine's own `apt-daily.timer` to refresh the lists |
| packages (dnf) | the same, security through `--security` | `dnf check-upgrade` from root's cache only, `rpm -qa` | any user; `dnf-makecache.timer`; a writable temporary directory |
| packages (apk) | pending upgrades | `apk --no-network version` | any user; an index from `apk update` |
| packages (pkg) | pending upgrades, vulnerable ones as security | `pkg upgrade -n -U`, `pkg audit -q`, `freebsd-version -kr` | any user |
| reboot | a newer kernel on disk than the one running | `/boot/vmlinuz-*`, else `/lib/modules` | nothing |
| containers | running containers of Podman or Docker: image as configured, the digests it runs | the runtime's API socket (`GET` only) | access to the socket, which is the same as being root: [how it is given](deploy/systemd/README.md#containers-how-access-to-podman-is-given) |
| backups (systemd) | whether the last run of a backup unit worked, and when one last did | `systemctl show <unit>` | any user; a state directory to remember the last success (`StateDirectory=` in the unit) |
| backups (file) | the newest file in a place where backups appear | the directory | read access to it |
| backups (restic) | the newest snapshot of a repository | `restic snapshots --latest 1 --no-lock` | restic, and read access to the repository's password |
| homeassistant | every update entity (Core, OS, apps, device firmware), the automatic backup | `GET /api/config`, `GET /api/states` | a long-lived access token, or the Supervisor's inside an app |
| opnsense | firmware, plugins, pending packages, the time of the firewall's last check | `GET /api/core/firmware/status` | an API key of a user with "System: Firmware" |

With no backup configured, a unit called `restic-backup.service` is reported when the machine
has one. The last two run on the server as connectors (`[[homeassistant]]`, `[[opnsense]]` in
`server.toml`), or in an agent as `[homeassistant]` and `[opnsense]`.

The server asks registries itself; agents never do. It makes one `HEAD` request for what a tag
points at now and reads the tag list, anonymously, which Docker Hub, ghcr.io, lscr.io and
quay.io answer for public images. Images under `localhost/` and images pinned by digest alone
are not asked about.

## The dashboard and the API

| Address | What it is |
|---|---|
| `/` | the numbers, what needs attention, every system in one table |
| `/updates` | everything that can be updated, system by system |
| `/backups` | every backup of every system |
| `/systems/<name>` | all of one system, with its raw report |
| `POST /api/v1/report` | an agent's report, with `Authorization: Bearer <token>` |
| `GET /api/v1/state` | systems, registry answers and findings as JSON, with the shared token |
| `DELETE /api/v1/systems/<name>` | forget a system that no longer exists, with the shared token |
| `GET /healthz` | `ok` |

A system that has not reported for two hours is shown as silent, and stays until it reports
again or is forgotten:

```sh
curl -X DELETE -H "Authorization: Bearer $(cat /etc/upkeep/token)" http://<server>:8484/api/v1/systems/<name>
```

## Configuration

Both example files show every setting with its default and what it is for, and the tests
load them, so they cannot go out of date: [deploy/server.toml](deploy/server.toml) and
[deploy/agent.toml](deploy/agent.toml). A setting upkeep does not know is an error. Secrets are
never in a configuration file; the files name the files that hold them.

## Deploying

### The server under Podman

```sh
scripts/build.sh 0.1.0
podman build -t localhost/upkeep:latest .                  # for this machine's architecture
podman build --platform linux/arm64 -t localhost/upkeep:latest .   # or for another one
```

Move the image to the host if it was built elsewhere (`podman save localhost/upkeep:latest`
there, `podman load` here). On the host, as root:

```sh
mkdir -p /etc/upkeep
od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > /etc/upkeep/token
cp deploy/server.toml /etc/upkeep/server.toml              # then edit: appliances, mail
chown -R root:65532 /etc/upkeep && chmod 0750 /etc/upkeep && chmod 0640 /etc/upkeep/*
cp deploy/quadlet/upkeep.container deploy/quadlet/upkeep-data.volume /etc/containers/systemd/
systemctl daemon-reload
systemctl start upkeep.service
```

The container runs as uid 65532 with a read-only file system and no capabilities; its data is
in the volume `upkeep-data`. See the comments in [deploy/quadlet/upkeep.container](deploy/quadlet/upkeep.container).

### Agents

| Where | How |
|---|---|
| Debian and other systemd machines | [deploy/systemd](deploy/systemd/README.md): an unprivileged user, a hardened unit, and a Podman socket for it |
| OPNsense, FreeBSD | [deploy/opnsense](deploy/opnsense/README.md): `install.sh`, an `rc.d` service and OPNsense's boot hook. Usually not needed: the server can ask the firewall itself |
| Home Assistant OS | [deploy/homeassistant/upkeep-agent](deploy/homeassistant/upkeep-agent/README.md): a local app. Usually not needed either |

## What to know before relying on it

- **The server speaks plain HTTP.** Tokens and reports cross the network in the clear. On a
  network that is not yours alone, put a reverse proxy with a certificate in front and give
  agents the `https://` address. The agent warns once when it sends over plain HTTP.
- **The dashboard is open** to whoever reaches the port unless `[dashboard]` sets a password.
  It names every machine and what is out of date on it.
- **The shared token can report any name**, so one agent could overwrite another system's row.
  Give a system a token of its own in `[tokens]` and only that token can report it.
- **Access to a container runtime's socket is root.** The agent only reads from it, but the
  socket cannot tell. Decide per machine.
- **The server only knows systems that reported once.** An agent that was never set up right
  is not on the dashboard at all; check for `report sent` in its log after installing.
- **An OPNsense API key can do more than read.** OPNsense has one privilege for the whole
  firmware API.

## Development

```sh
go vet ./... && go test -race ./...
go test -tags e2e -count=1 -v -timeout 20m ./internal/e2e    # the real binary, end to end
```

The end-to-end test starts `upkeep server` as a process, lets real agents report to it (this
machine, and with Podman a Debian container), and puts stand-ins in place of the appliances
and the registries; see [internal/e2e/doc.go](internal/e2e/doc.go). `UPKEEP_E2E_LIVE=1` adds
one look at the real registries.

The code, by directory: `internal/agent` and `internal/collect/*` (the agent and what it
looks at), `internal/connect/*` (appliances), `internal/registry` (what is newer),
`internal/server`, `internal/store`, `internal/model` (what counts as a finding),
`internal/web` (the dashboard), `internal/notify` (the mail), `internal/report` (the format
every source speaks).
