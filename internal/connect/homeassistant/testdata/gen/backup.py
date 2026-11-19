"""Configure a daily automatic backup on a throwaway instance and run it once."""
import asyncio, json, os, sys
import aiohttp

async def main():
    token = os.environ["HA_TOKEN"]
    fail = os.environ.get("FAIL") == "1"
    async with aiohttp.ClientSession() as s, s.ws_connect("http://127.0.0.1:8123/api/websocket") as ws:
        await ws.receive_json()
        await ws.send_json({"type": "auth", "access_token": token})
        print((await ws.receive_json())["type"])
        n = 0
        async def call(msg):
            nonlocal n
            n += 1
            msg["id"] = n
            await ws.send_json(msg)
            while True:
                r = await ws.receive_json()
                if r.get("id") == n and r.get("type") == "result":
                    return r
        agents = ["backup.does_not_exist"] if fail else ["backup.local"]
        r = await call({"type": "backup/config/update", "automatic_backups_configured": True,
                        "create_backup": {"agent_ids": agents, "include_database": False, "password": "fixture-only"},
                        "schedule": {"recurrence": "daily"}})
        print("config", r.get("success"), r.get("error"))
        r = await call({"type": "backup/generate_with_automatic_settings"})
        print("generate", r.get("success"), r.get("error"), r.get("result"))

asyncio.run(main())
