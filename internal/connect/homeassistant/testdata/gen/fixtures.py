"""Builds internal/connect/homeassistant/testdata from the captures of a real Home Assistant.

usage: fixtures.py CAPTURE_DIR TESTDATA_DIR
"""
import json
import re
import shutil
import sys

cap, out = sys.argv[1], sys.argv[2]


def dump(states):
    # Home Assistant writes compact JSON with non-ASCII characters as they are.
    return json.dumps(states, separators=(",", ":"), ensure_ascii=False)


def wanted(e):
    i = e["entity_id"]
    return i.startswith("update.") or "backup" in i or i in ("sun.sun", "zone.home", "person.fixture")


# Byte for byte as captured.
shutil.copyfile(cap + "/config.json", out + "/config.json")
# The whole answer, 124 entities. The demo cameras carry access tokens of the instance that was
# thrown away after the capture; they are zeroed so that nothing in the tree looks like a secret.
whole = open(cap + "/states-restart.json", encoding="utf-8").read()
whole = re.sub(r'("access_token":")[0-9a-f]{64}', lambda m: m.group(1) + "0" * 64, whole)
open(out + "/states-container.json", "w", encoding="utf-8").write(whole)
shutil.copyfile(cap + "/unauth.body", out + "/unauthorized.txt")

# Captured, with the entities this source does not look at left out to keep the files small.
for src, dst in (
    ("states.json", "states-first-start.json"),
    ("states-progress.json", "states-installing.json"),
    ("states-backup-ok.json", "states-backup-ok.json"),
):
    states = [e for e in json.load(open(cap + "/" + src, encoding="utf-8")) if wanted(e)]
    open(out + "/" + dst, "w", encoding="utf-8").write(dump(states))

# Built by hand for an installation with a Supervisor, which a container cannot have. The shape of
# every entity is the one captured above; the values that tell the entities apart are the ones
# homeassistant/components/hassio/update.py, esphome/update.py, uptime_kuma/update.py and HACS'
# update.py set.
real = json.load(open(cap + "/states-backup-ok.json", encoding="utf-8"))
by_id = {e["entity_id"]: e for e in real}
stamp = "2026-11-18T23:45:14.934733+00:00"
n = 0


def context():
    global n
    n += 1
    return {"id": "01M7RGSQNP%016d" % n, "parent_id": None, "user_id": None}


def update(entity_id, state, installed, latest, title, friendly, features, picture=None, url=None, device_class=None,
           skipped=None, auto=False, summary=None):
    a = {
        "auto_update": auto, "display_precision": 0, "installed_version": installed, "in_progress": False,
        "latest_version": latest, "release_summary": summary, "release_url": url, "skipped_version": skipped,
        "title": title, "update_percentage": None,
    }
    if device_class:
        a["device_class"] = device_class
    if picture:
        a["entity_picture"] = picture
    a["friendly_name"] = friendly
    a["supported_features"] = features
    return {"entity_id": entity_id, "state": state, "attributes": a, "last_changed": stamp, "last_reported": stamp,
            "last_updated": stamp, "context": context()}


def with_state(entity_id, state, attributes=None):
    e = json.loads(json.dumps(by_id[entity_id]))
    e["state"] = state
    if attributes is not None:
        e["attributes"].update(attributes)
    return e


INSTALL, SPECIFIC, PROGRESS, BACKUP, NOTES = 1, 2, 4, 8, 16
haos = [
    by_id["sun.sun"],
    by_id["zone.home"],
    # The Supervisor's own three.
    update("update.home_assistant_supervisor_update", "off", "2026.11.0", "2026.11.0", "Home Assistant Supervisor",
           "Home Assistant Supervisor Update", INSTALL | PROGRESS,
           picture="/api/brands/integration/hassio/icon.png?placeholder=no",
           url="https://github.com/home-assistant/supervisor/releases/tag/2026.11.0", auto=True),
    update("update.home_assistant_core_update", "on", "2026.11.1", "2026.11.2", "Home Assistant Core",
           "Home Assistant Core Update", INSTALL | SPECIFIC | BACKUP | PROGRESS,
           picture="/api/brands/integration/homeassistant/icon.png?placeholder=no",
           url="https://www.home-assistant.io/latest-release-notes/"),
    update("update.home_assistant_operating_system_update", "on", "18.4", "18.5", "Home Assistant Operating System",
           "Home Assistant Operating System Update", INSTALL | SPECIFIC | BACKUP | NOTES,
           picture="/api/brands/integration/homeassistant/icon.png?placeholder=no",
           url="https://github.com/home-assistant/operating-system/releases/tag/18.5"),
    # Apps: one up to date, one with an update, one whose update was skipped, one without an icon.
    update("update.mosquitto_broker_update", "off", "6.5.2", "6.5.2", "Mosquitto broker", "Mosquitto broker Update",
           INSTALL | BACKUP | NOTES | PROGRESS, picture="/api/hassio/addons/core_mosquitto/icon"),
    update("update.zigbee2mqtt_update", "on", "2.6.3-1", "2.7.0-1", "Zigbee2MQTT", "Zigbee2MQTT Update",
           INSTALL | BACKUP | NOTES | PROGRESS, picture="/api/hassio/addons/45df7312_zigbee2mqtt/icon"),
    update("update.esphome_device_builder_update", "off", "2026.10.3", "2026.11.0", "ESPHome Device Builder",
           "ESPHome Device Builder Update", INSTALL | BACKUP | NOTES | PROGRESS,
           picture="/api/hassio/addons/5c53de3b_esphome/icon", skipped="2026.11.0"),
    update("update.upkeep_agent_update", "off", "0.3.0", "0.3.0", "upkeep agent", "upkeep agent Update",
           INSTALL | BACKUP | NOTES | PROGRESS),
    # An integration installed through HACS.
    update("update.adaptive_lighting_update", "on", "1.25.0", "1.26.0", None, "Adaptive Lighting update",
           INSTALL | SPECIFIC | PROGRESS | NOTES, picture="https://brands.home-assistant.io/_/adaptive_lighting/icon.png",
           url="https://github.com/basnijholt/adaptive-lighting/releases/1.26.0"),
    # Other software that an integration watches.
    update("update.uptime_example_net_uptime_kuma_version", "on", "2.0.2", "2.1.0", "Uptime Kuma 2.1.0",
           "uptime.example.net Uptime Kuma version", NOTES, picture="/api/brands/integration/uptime_kuma/icon.png",
           url="https://github.com/louislam/uptime-kuma/releases/tag/2.1.0"),
    # Device firmware: the title is the same for every device.
    update("update.bedroom_sensor_firmware", "on", "2026.10.3", "2026.11.0", "ESPHome", "Bedroom sensor Firmware", INSTALL,
           picture="/api/brands/integration/esphome/icon.png", url="https://esphome.io/changelog/", device_class="firmware"),
    update("update.hallway_sensor_firmware", "off", "2026.11.0", "2026.11.0", "ESPHome", "Hallway sensor Firmware", INSTALL,
           picture="/api/brands/integration/esphome/icon.png", url="https://esphome.io/changelog/", device_class="firmware"),
    # Automatic backups on Monday and Thursday; the last one, on Monday, worked.
    with_state("event.backup_automatic_backup", "2026-11-16T04:52:13.412+00:00"),
    with_state("sensor.backup_backup_manager_state", "idle"),
    with_state("sensor.backup_next_scheduled_automatic_backup", "2026-11-19T05:12:07+00:00"),
    with_state("sensor.backup_last_successful_automatic_backup", "2026-11-16T04:52:13+00:00"),
    with_state("sensor.backup_last_attempted_automatic_backup", "2026-11-16T04:45:41+00:00"),
    with_state("sensor.backup_last_successful_automatic_backup_size", "418.7421875"),
]
open(out + "/states-haos.json", "w", encoding="utf-8").write("[\n" + ",\n".join(dump(e) for e in haos) + "\n]\n")

# The same installation while an automatic backup runs: the attempt is stamped, the success is not yet.
running = [e for e in haos if "backup" in e["entity_id"]]
for e in running:
    if e["entity_id"] == "sensor.backup_backup_manager_state":
        e["state"] = "create_backup"
    elif e["entity_id"] == "sensor.backup_last_attempted_automatic_backup":
        e["state"] = "2026-11-19T05:12:07+00:00"
    elif e["entity_id"] == "sensor.backup_next_scheduled_automatic_backup":
        e["state"] = "2026-11-23T04:58:40+00:00"
    elif e["entity_id"] == "event.backup_automatic_backup":
        e["state"] = "2026-11-19T05:12:07.105+00:00"
        e["attributes"].update({"event_type": "in_progress", "backup_stage": "upload_to_agents"})
open(out + "/states-haos-backup-running.json", "w", encoding="utf-8").write("[\n" + ",\n".join(dump(e) for e in running) + "\n]\n")

config = json.load(open(cap + "/config.json", encoding="utf-8"))
config["version"] = "2026.11.1"
config["components"] = sorted(config["components"] + ["hassio"])
open(out + "/config-haos.json", "w", encoding="utf-8").write(dump(config))
starting = json.load(open(cap + "/config.json", encoding="utf-8"))
starting["state"] = "STARTING"
open(out + "/config-starting.json", "w", encoding="utf-8").write(dump(starting))
