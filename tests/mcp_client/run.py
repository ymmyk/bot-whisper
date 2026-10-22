import asyncio, json
from contextlib import AsyncExitStack
from common import bot, call
def short(d):
    s=json.dumps(d) if not isinstance(d,str) else d
    return s[:500]
async def C(b, name, tool, **a):
    if tool in ('send_message','set_turn'): await asyncio.sleep(2.1)
    err,d=await call(b,tool,**a)
    print(f"  {name}.{tool}({', '.join(k for k in a)}) -> {'ERR ' if err else ''}{short(d)}")
    return err,d
def rid(d): return d.get("room_id") if isinstance(d,dict) else None
async def mk(b1, others, title, mode=None):
    kw={"title":title,"display_name":"bot1"}
    if mode: kw["turn_mode"]=mode
    _,d=await C(b1,"bot1","create_room",**kw); r=rid(d)
    for n,b in others:
        _,inv=await C(b1,"bot1","create_invite",room_id=r,label=n)
        await C(b,n,"join_room",invite_url=inv["invite_url"],display_name=n)
    return r
async def main():
    async with AsyncExitStack() as st:
        b1=await st.enter_async_context(bot("bot1")); b2=await st.enter_async_context(bot("bot2")); b3=await st.enter_async_context(bot("bot3"))
        print("=== T1 two bots, ack then re-read")
        r=await mk(b1,[("bot2",b2)],"T1","alternate")
        await C(b1,"bot1","send_message",room_id=r,text="hello from bot1")
        await C(b2,"bot2","wait_for_message",room_id=r,timeout_s=5)
        await C(b2,"bot2","send_message",room_id=r,text="hi bot1, bot2 here")
        await C(b1,"bot1","wait_for_message",room_id=r,timeout_s=5)
        await C(b1,"bot1","send_message",room_id=r,text="third message")
        await C(b2,"bot2","wait_for_message",room_id=r,timeout_s=5)
        print("  -- re-read after acks (expect empty)")
        await C(b1,"bot1","wait_for_message",room_id=r,timeout_s=2,after_seq=0)
        await C(b2,"bot2","wait_for_message",room_id=r,timeout_s=2,after_seq=0)
        await C(b1,"bot1","get_status",room_id=r)
        print("=== T3 member done -> OWNER_ONLY, owner done closes thread")
        await C(b2,"bot2","send_message",room_id=r,text="bot2 trying to end",turn="done")
        await C(b2,"bot2","set_turn",room_id=r,signal="done")
        await C(b2,"bot2","send_message",room_id=r,text="ok, back to you")
        await C(b1,"bot1","wait_for_message",room_id=r,timeout_s=5)
        await C(b1,"bot1","send_message",room_id=r,text="wrapping up",turn="done")
        await C(b2,"bot2","wait_for_message",room_id=r,timeout_s=5)
        await C(b2,"bot2","get_status",room_id=r)
        await C(b2,"bot2","send_message",room_id=r,text="after done")
        print("=== T2 three bots round robin, cap 4")
        r=await mk(b1,[("bot2",b2),("bot3",b3)],"T2","alternate")
        await C(b1,"bot1","start_thread",room_id=r,topic="rr test",turn_mode="round_robin",turn_cap=4)
        await C(b3,"bot3","send_message",room_id=r,text="bot3 out of turn")
        await C(b1,"bot1","send_message",room_id=r,text="rr1 bot1")
        await C(b3,"bot3","send_message",room_id=r,text="bot3 out of turn again")
        await C(b2,"bot2","send_message",room_id=r,text="rr2 bot2")
        await C(b3,"bot3","send_message",room_id=r,text="rr3 bot3")
        await C(b1,"bot1","get_status",room_id=r)
        await C(b1,"bot1","send_message",room_id=r,text="rr4 bot1 (cap)")
        await C(b2,"bot2","send_message",room_id=r,text="rr5 bot2 over cap")
        await C(b3,"bot3","wait_for_message",room_id=r,timeout_s=3)
        await C(b1,"bot1","get_status",room_id=r)
        print("=== T4 owner leaves -> room closes")
        await C(b1,"bot1","leave_room",room_id=r)
        await C(b2,"bot2","get_status",room_id=r)
        await C(b3,"bot3","send_message",room_id=r,text="anyone?")
        await C(b3,"bot3","wait_for_message",room_id=r,timeout_s=3)
        await C(b2,"bot2","list_rooms")
        await C(b1,"bot1","list_rooms")
        for x in (await call(b1,"list_rooms"))[1]["rooms"]: await C(b1,"bot1","close_room",room_id=x["room_id"])
asyncio.run(main())
