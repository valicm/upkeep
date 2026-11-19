# The agent on OPNsense or FreeBSD

**You may not need it.** The upkeep server can ask an OPNsense firewall itself: an
`[[opnsense]]` table in `server.toml` with the firewall's address and an API key gives the same
rows on the dashboard, with nothing installed on the firewall. Install the agent when the
server cannot reach the firewall's web interface, or on a plain FreeBSD machine.

## Install

Copy this directory and `dist/upkeep-freebsd-amd64` to the firewall, then as root:

```sh
sh install.sh upkeep-freebsd-amd64
```

It prints what is left to do: the server's address, the token, the API key, a look at the
report, the start. It installs:

| File | What it is |
|---|---|
| `/usr/local/bin/upkeep` | the binary |
| `/usr/local/etc/upkeep/agent.toml`, `token` | configuration and token, mode 0640, group `upkeep` |
| `/usr/local/etc/rc.d/upkeep_agent` | the service: `service upkeep_agent start|stop|status` |
| `/etc/rc.conf.d/upkeep_agent` | `upkeep_agent_enable="YES"` |
| `/usr/local/etc/rc.syshook.d/start/50-upkeep` | OPNsense only: starts the service at the end of the firewall's boot |

and a user `upkeep` without password, shell or home, which the agent runs as.

## Why the hook

OPNsense does not boot through FreeBSD's `rc`. At the end of its own start it runs the scripts
under `/usr/local/etc/rc.syshook.d/start/`. One of OPNsense's own (`20-freebsd`) starts the
`rc.d` services that are enabled in `/etc/rc.conf.d/`, which by the source of OPNsense 26.7
would start this one as well; `50-upkeep` does not rely on that. It asks the service whether
it runs and starts it if not, so the agent is up after a boot either way and never twice.

## What the agent's user needs

- To read `/usr/local/etc/upkeep/token` and, with the `[opnsense]` table, the API key file.
- Nothing else. With `[packages] enabled = true` it runs `pkg upgrade -n -U`, `pkg audit -q`
  and `freebsd-version -kr`, which a normal user may.

The API key belongs to an OPNsense user with the single privilege "System: Firmware". That
privilege is all-or-nothing in OPNsense: it also allows installing updates and rebooting. The
agent only sends `GET /api/core/firmware/status` (and, with `check = true`, asks for a check).

## Remove

```sh
service upkeep_agent stop
rm /usr/local/etc/rc.syshook.d/start/50-upkeep /usr/local/etc/rc.d/upkeep_agent /etc/rc.conf.d/upkeep_agent /usr/local/bin/upkeep
rm /usr/local/etc/upkeep/agent.toml /usr/local/etc/upkeep/token && rmdir /usr/local/etc/upkeep
pw userdel upkeep
```

## Not tested on a firewall

No OPNsense or FreeBSD machine was at hand: the binary is cross-built, the scripts are checked
for syntax only, and what OPNsense does at boot and with user accounts is read in its source
(opnsense/core, stable/26.7: `src/etc/rc.syshook`, `src/etc/rc.freebsd`, `src/etc/inc/auth.inc`).
Run `install.sh` on the standby firewall first.
