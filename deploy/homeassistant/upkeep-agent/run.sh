#!/bin/sh
# Turns the app's options (/data/options.json, written by the Supervisor) into the agent's
# configuration and starts the agent. DATA is only set differently by tests.
set -eu

data=${DATA:-/data}
options=$data/options.json

if [ -z "$(jq -r '.server // empty' "$options")" ] || [ -z "$(jq -r '.token // empty' "$options")" ]; then
	echo "upkeep agent: set the server's address and the token on the app's Configuration tab" >&2
	exit 1
fi

# Home Assistant's base image starts this script through s6, which hands a command a clean
# environment and keeps the container's own in files: the Supervisor's token is there.
if [ -z "${SUPERVISOR_TOKEN:-}" ] && [ -r /run/s6/container_environment/SUPERVISOR_TOKEN ]; then
	SUPERVISOR_TOKEN=$(cat /run/s6/container_environment/SUPERVISOR_TOKEN)
	export SUPERVISOR_TOKEN
fi

umask 077
jq -r '.token' "$options" >"$data/token"

# jq writes each value as a quoted string, which TOML reads the same way: nothing typed
# into an option can become a setting of its own.
jq -r --arg token_file "$data/token" '
	"# Written by run.sh from the app'"'"'s options at every start.",
	"server = \(.server | tojson)",
	"token_file = \($token_file | tojson)",
	"name = \(.name // "homeassistant" | tojson)",
	"interval = \(.interval // "15m" | tojson)",
	"",
	"# This is a container: its packages, containers and backups are not Home Assistant'"'"'s.",
	"[packages]",
	"enabled = false",
	"[containers]",
	"enabled = false",
	"[backups]",
	"enabled = false",
	"",
	"# Home Assistant itself, through the Supervisor.",
	"[homeassistant]",
	"supervisor = true"
' "$options" >"$data/agent.toml"

exec /usr/local/bin/upkeep agent -config "$data/agent.toml"
