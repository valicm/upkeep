# The agent as a systemd service

Four files, for a Debian (or any systemd) machine. Everything below runs as root.

| File | Goes to | What it is |
|---|---|---|
| `upkeep.sysusers` | `/etc/sysusers.d/upkeep.conf` | the user and group `upkeep` |
| `upkeep-agent.service` | `/etc/systemd/system/` | the agent, as that user |
| `upkeep-podman.socket`, `upkeep-podman.service` | `/etc/systemd/system/` | only on machines with rootful Podman: a socket the agent may use |

```sh
install -m 0755 upkeep-linux-amd64 /usr/local/bin/upkeep          # or -arm64, -armv7
install -m 0644 upkeep.sysusers /etc/sysusers.d/upkeep.conf
systemd-sysusers /etc/sysusers.d/upkeep.conf

install -d -m 0750 -g upkeep /etc/upkeep
install -m 0640 -g upkeep ../agent.toml /etc/upkeep/agent.toml    # then set "server" in it
install -m 0640 -g upkeep /dev/null /etc/upkeep/token             # then put the token into it, one line

install -m 0644 upkeep-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now upkeep-agent.service
journalctl -u upkeep-agent.service -n 20
```

The log says `report sent: ...` once the server took the first report. To see what the agent
would send without sending it, as its own user:

```sh
setpriv --reuid=upkeep --regid=upkeep --clear-groups /usr/local/bin/upkeep agent -config /etc/upkeep/agent.toml -print
```

## What the agent's user can and cannot read

It is an ordinary user without a password, a shell or any capability, and the unit makes the
whole file system read-only for it except `/var/lib/upkeep-agent` and a private `/tmp`.

- **Packages**: apt's simulation, dnf's cache and the reboot flag are readable by every user.
- **Backups**: `systemctl show` of a unit is allowed to every user, so the state of
  `restic-backup.service` is reported without more. A `[[backups.restic]]` job needs the
  repository's password: the agent's user would have to read that file, and by default it
  cannot. Either leave it at the systemd evidence, or give the group `upkeep` read access to
  an environment file on purpose.
- **Token**: `/etc/upkeep/token`, mode 0640, group `upkeep`.

## Containers: how access to Podman is given

Rootful Podman answers on `/run/podman/podman.sock` once `podman.socket` is enabled, but that
directory is `0700 root` (Podman's own tmpfiles.d rule), so a group on that socket would not
help. Instead the agent gets a socket of its own:

```sh
install -m 0644 upkeep-podman.socket upkeep-podman.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now upkeep-podman.socket
```

and in `/etc/upkeep/agent.toml`:

```toml
[containers]
sockets = ["/run/upkeep-podman/podman.sock"]
```

The socket is `/run/upkeep-podman/podman.sock`, owner `root`, group `upkeep`, mode `0660`: the
agent's user is in that group and nobody else is. **This is the one real privilege the agent
has**: Podman's API has no read-only mode, so whoever can open that socket can do everything
rootful Podman can, which is everything root can. The agent only lists and inspects, and the
unit's restrictions apply to the agent's own process, not to what the socket would do for it.
If that is more than a machine should give, set `enabled = false` in `[containers]` instead;
the dashboard then shows no containers for it.

A machine with Podman installed and no socket the agent can find is reported as a problem
("podman is installed but its API socket was not found"), not passed over in silence.

Docker: add the agent's user to the group `docker` (`usermod -aG docker upkeep`), with the
same warning, and the default `/var/run/docker.sock` is found by itself.
