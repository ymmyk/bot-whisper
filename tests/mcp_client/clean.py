import asyncio
from common import bot, call
async def main():
    async with bot("bot1") as s:
        for x in (await call(s,"list_rooms"))[1]["rooms"]: print(await call(s,"close_room",room_id=x["room_id"]))
asyncio.run(main())
