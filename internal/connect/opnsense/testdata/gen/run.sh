#!/bin/sh
# Rebuilds ../status-*.json by running OPNsense's real statusAction() over the inputs in in/.
# usage: run.sh /path/to/opnsense/core   (a checkout of github.com/opnsense/core, stable/26.7)
set -eu
core=${1:?usage: run.sh /path/to/opnsense/core}
here=$(cd "$(dirname "$0")" && pwd)
api="$core/src/opnsense/mvc/app/controllers/OPNsense/Core/Api"

status() { # output, core metadata, answers of the shell commands, check result or -
	check=$4
	[ "$check" = - ] || check="/gen/in/$check"
	podman run --rm --network none -v "$here:/gen:ro,Z" -v "$api:/api:ro,Z" \
		docker.io/library/php:8.3-cli-alpine \
		php /gen/harness.php /api/FirmwareController.php "/gen/in/$2" "/gen/in/$3" "$check" > "$here/../$1"
}

status status-update.json               core-26.7.8.json   extra-newer.json   check-update.json
status status-none.json                 core-26.7.8.json   extra-current.json check-none.json
status status-none-old.json             core-26.7.8.json   extra-current.json check-none-old.json
status status-none-changelog-newer.json core-26.7.8.json   extra-newer.json   check-none.json
status status-major.json                core-26.7.8.json   extra-current.json check-major.json
status status-error.json                core-26.7.8.json   extra-current.json check-error.json
status status-unchecked.json            core-26.7.8.json   extra-current.json -
status status-be-reboot.json            core-be-26.10.json extra-be.json      check-be-reboot.json
