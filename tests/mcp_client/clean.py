import asyncio
from common import bot, call
async def main():
    async with bot("bot1") as s:
        print(await call(s,"close_room",room_id="424468fe-b9cf-409c-8564-d0e77aa76cc3"))
        print(await call(s,"list_rooms"))
asyncio.run(main())
