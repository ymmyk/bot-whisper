import asyncio, json
from common import bot
async def main():
    async with bot("bot1") as s:
        t=await s.list_tools()
        for x in t.tools: print(x.name, json.dumps(x.input_schema.get("properties",{}))[:400])
asyncio.run(main())
