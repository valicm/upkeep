#!/bin/sh
# Captures real answers of Home Assistant's REST API from a throwaway container.
# usage: capture.sh CAPTURE_DIR   (then: fixtures.py CAPTURE_DIR ../)
#
# These are the commands the captures in this directory were made with, collected into one
# script afterwards. The script as a whole has not been run again: a new run gives new time
# stamps, and the expected values in homeassistant_test.go have to follow.
set -eu
cap=${1:?usage: capture.sh CAPTURE_DIR}
here=$(cd "$(dirname "$0")" && pwd)
image=ghcr.io/home-assistant/home-assistant:2026.11.2
name=upkeep-fixture-homeassistant
base=http://127.0.0.1:18123
mkdir -p "$cap/config"
umask 077

# The demo integration brings update entities, default_config the backup integration.
printf 'default_config:\ndemo:\n' > "$cap/config/configuration.yaml"
podman run -d --name $name --memory 1500m -p 127.0.0.1:18123:8123 -e TZ=UTC -v "$cap/config:/config:Z" $image
until curl -fsS -m 5 -o /dev/null $base/api/onboarding; do sleep 5; done

# The first user of a new instance, and a token for it.
password=$(head -c 18 /dev/urandom | base64)
code=$(curl -fsS -H 'Content-Type: application/json' \
	-d "{\"client_id\":\"$base/\",\"name\":\"Fixture\",\"username\":\"fixture\",\"password\":\"$password\",\"language\":\"en\"}" \
	$base/api/onboarding/users | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["auth_code"])')
token=$(curl -fsS --data-urlencode grant_type=authorization_code --data-urlencode "code=$code" \
	--data-urlencode "client_id=$base/" $base/auth/token | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
get() { curl -fsS -m 30 -H "Authorization: Bearer $token" "$base/api/$1" -o "$cap/$2"; }
call() { curl -fsS -m 60 -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$2" "$base/api/services/$1" -o /dev/null; }

get config config.json
get states states.json
curl -sS -m 20 -D "$cap/unauth.headers" -H 'Authorization: Bearer not-a-real-token' $base/api/states -o "$cap/unauth.body"

# Skip one update, and look while another is being installed.
call update/skip '{"entity_id":"update.demo_add_on"}'
call update/install '{"entity_id":"update.demo_update_with_progress"}' &
sleep 2.5
get states states-progress.json
wait

# An automatic backup that works, then one that fails.
podman exec -i -e HA_TOKEN="$token" $name python3 - < "$here/backup.py"
sleep 6
get states states-backup-ok.json
podman exec -i -e FAIL=1 -e HA_TOKEN="$token" $name python3 - < "$here/backup.py" || true
sleep 6
get states states-backup-failed.json

# A device that is offline and a version nobody knows, as template entities; then a restart.
cat >> "$cap/config/configuration.yaml" <<'YAML'
template:
  - update:
      - name: "Fixture offline plug firmware"
        device_class: firmware
        installed_version: "{{ '1.0.0' }}"
        latest_version: "{{ '1.1.0' }}"
        availability: "{{ false }}"
      - name: "Fixture version unknown"
        installed_version: "{{ '2.3.1' }}"
        latest_version: "{{ none }}"
YAML
podman restart -t 20 $name
until [ "$(curl -fsS -m 5 -H "Authorization: Bearer $token" $base/api/config | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["state"])' 2>/dev/null)" = RUNNING ]; do sleep 5; done
sleep 10
get states states-restart.json

podman rm -f $name
