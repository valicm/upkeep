#!/bin/sh
# Installs the upkeep agent on OPNsense, or on any FreeBSD. Run as root on the machine itself,
# from a directory that holds this script, upkeep_agent, 50-upkeep, agent.toml and the binary:
#
#   sh install.sh [path/to/upkeep-freebsd-amd64]
#
# It can be run again to put a newer binary in place: a configuration and a token that are
# already there are left alone.
set -eu

dir=$(cd "$(dirname "$0")" && pwd)
binary=${1:-$dir/upkeep-freebsd-amd64}
etc=/usr/local/etc/upkeep

if [ "$(id -u)" != 0 ]; then
	echo "install.sh: run this as root" >&2
	exit 1
fi
if [ "$(uname -s)" != FreeBSD ]; then
	echo "install.sh: this is for FreeBSD and OPNsense, not $(uname -s)" >&2
	exit 1
fi
for file in "$binary" "$dir/upkeep_agent" "$dir/50-upkeep" "$dir/agent.toml"; do
	if [ ! -f "$file" ]; then
		echo "install.sh: $file is missing" >&2
		exit 1
	fi
done

# A user of its own, without a password, a shell or a home. OPNsense rewrites the accounts
# it manages (uid 2000 to 65000) and leaves the others alone; pw gives a new user a uid from
# 1001 up, so this one stays.
if ! pw usershow upkeep >/dev/null 2>&1; then
	pw useradd -n upkeep -c "upkeep agent" -d /nonexistent -s /usr/sbin/nologin -w no
fi
uid=$(id -u upkeep)
if [ "$uid" -ge 2000 ] && [ "$uid" -le 65000 ]; then
	echo "install.sh: warning: the user upkeep has uid $uid, in the range OPNsense manages; it may be removed when users are saved" >&2
fi

install -m 0755 "$binary" /usr/local/bin/upkeep
install -d -m 0750 -o root -g upkeep "$etc"
if [ ! -f "$etc/agent.toml" ]; then
	install -m 0640 -o root -g upkeep "$dir/agent.toml" "$etc/agent.toml"
fi
if [ ! -f "$etc/token" ]; then
	install -m 0640 -o root -g upkeep /dev/null "$etc/token"
fi

install -m 0755 "$dir/upkeep_agent" /usr/local/etc/rc.d/upkeep_agent
mkdir -p /etc/rc.conf.d
echo 'upkeep_agent_enable="YES"' >/etc/rc.conf.d/upkeep_agent

# OPNsense only: the hook its own boot runs.
if [ -d /usr/local/etc/rc.syshook.d ]; then
	install -d -m 0755 /usr/local/etc/rc.syshook.d/start
	install -m 0755 "$dir/50-upkeep" /usr/local/etc/rc.syshook.d/start/50-upkeep
fi

/usr/local/bin/upkeep version
if /usr/local/etc/rc.d/upkeep_agent status >/dev/null 2>&1; then
	/usr/local/etc/rc.d/upkeep_agent restart
	exit 0
fi
cat <<END

Installed, not started yet. What is left:

  1. $etc/agent.toml: set "server".
  2. $etc/token: put the upkeep server's token into it, one line.
  3. $etc/apikey.txt: the API key file of an OPNsense user with the privilege
     "System: Firmware", then:  chown root:upkeep $etc/apikey.txt && chmod 0640 $etc/apikey.txt
  4. Look at what would be sent:
       su -m upkeep -c '/usr/local/bin/upkeep agent -config $etc/agent.toml -print'
  5. Start it:  service upkeep_agent start
     Its log is in the system log (System > Log Files > General), under upkeep_agent.
END
