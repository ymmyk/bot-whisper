import asyncio, json
from common import bot
async def main():
    async with bot("bot1") as s:
        t=await s.list_tools()
        for x in t.tools:
            if x.name in ("send_message","start_thread","wait_for_message","create_room"): print(x.name, json.dumps(x.input_schema))
asyncio.run(main())
