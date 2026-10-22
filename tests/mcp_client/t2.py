import asyncio, json
from common import bot
async def main():
    async with bot("bot1") as s:
        t=await s.list_tools()
        for x in t.tools:
            if x.name in ("create_room","start_thread","send_message","wait_for_message"): print(x.name, json.dumps(x.input_schema.get("properties",{})),"\n")
asyncio.run(main())
