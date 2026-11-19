# upkeep agent as a Home Assistant app

For Home Assistant OS (or Supervised). The agent runs as a local app and reports what Home
Assistant knows itself: every update entity (Core, the operating system, the Supervisor, apps,
device firmware) and the state of the automatic backup. On the dashboard the system shows as
Home Assistant, with its own versions.

You do not need this app when the upkeep server can reach Home Assistant: a `[[homeassistant]]`
table in the server's configuration with a long-lived access token gives the same rows, with
nothing installed. The app is for a Home Assistant the server cannot reach, and it needs no
long-lived token.

## Install

1. Copy this directory to the Home Assistant machine as `/addons/upkeep-agent` (Samba share
   "addons", or the SSH app).
2. Copy the upkeep binary for the machine next to `config.yaml`, named `upkeep`:
   `upkeep-linux-arm64` for a Raspberry Pi, Green or Yellow; `upkeep-linux-amd64` for a PC.
3. In Home Assistant: Settings, Apps, App store, the menu at the top right, "Check for
   updates". "upkeep agent" appears under "Local apps". Install it.
4. On its Configuration tab set `server` (for example `http://upkeep.example.net:8484`) and
   `token` (the upkeep server's token, or this system's own from its `[tokens]` table), and
   `name` if "homeassistant" is taken. Start the app.
5. The Log tab says `report sent: ...` within a few seconds.

## What it may do

`homeassistant_api: true` is the app's only permission. It lets the app call Home Assistant's
own API through the Supervisor (`http://supervisor/core`) with the token the Supervisor hands
every app; the agent makes two GET requests there, `/api/config` and `/api/states`. It has no
access to the Supervisor's API, the host network, devices or shares, and it changes nothing.

It also makes one request out: the report, to the server you set. The token is kept in the
app's own data directory, readable by the app alone.

## Not tested on a real Home Assistant

The app was built on Home Assistant's base image and run next to a stand-in for the
Supervisor's proxy; no Home Assistant OS installation was at hand. What the Supervisor answers
to an app, and how it builds a local app in its current version, is from its documentation.
