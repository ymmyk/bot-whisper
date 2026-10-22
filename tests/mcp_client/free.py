import asyncio, json, time
from contextlib import AsyncExitStack
from common import bot, call, TOK, URL
import httpx2
def sh(d): return (json.dumps(d) if not isinstance(d,str) else d)[:260]
async def mk(b1, others, title, **kw):
    _,d=await call(b1,"create_room",title=title,display_name="bot1",**kw); r=d["room_id"]; print("create",sh(d))
    for n,b in others:
        _,inv=await call(b1,"create_invite",room_id=r,label=n)
        await call(b,"join_room",invite_url=inv["invite_url"],display_name=n)
    return r
async def main():
    async with AsyncExitStack() as st:
        bs={n: await st.enter_async_context(bot(n)) for n in ("bot1","bot2","bot3")}
        b1,b2,b3=bs["bot1"],bs["bot2"],bs["bot3"]
        print("=== F1 free mode, simultaneous sends")
        r=await mk(b1,[("bot2",b2),("bot3",b3)],"F1")
        await call(b1,"start_thread",room_id=r,topic="free cap",turn_cap=6)
        errs={}
        for rnd in range(3):
            res=await asyncio.gather(*[call(bs[n],"send_message",room_id=r,text=f"{n} r{rnd}") for n in bs])
            for n,(e,d) in zip(bs,res):
                print(f"  r{rnd} {n}:", "ERR" if e else "ok", sh(d) if e else f"seq={d.get('seq')} used={(d.get('turn_state') or {}).get('turns_used')} status={(d.get('turn_state') or {}).get('status')} now={(d.get('turn_state') or {}).get('now')}")
                if e: errs.setdefault(d.get("error") if isinstance(d,dict) else d,0); errs[d.get("error") if isinstance(d,dict) else d]+=1
            await asyncio.sleep(2.2)
        print("  error counts:",errs)
        print("=== F2 loop guard: rapid burst from one bot, free mode")
        r2=await mk(b1,[("bot2",b2)],"F2")
        for i in range(4):
            e,d=await call(b2,"send_message",room_id=r2,text=f"burst {i}")
            print(f"  burst{i}:", "ERR "+sh(d) if e else f"ok seq={d.get('seq')}")
        print("=== F2b ping-pong loop: two bots alternate quickly with 2.1s spacing, up to 30 msgs")
        r3=await mk(b1,[("bot2",b2)],"F3")
        tripped=None
        for i in range(30):
            n="bot1" if i%2==0 else "bot2"
            e,d=await call(bs[n],"send_message",room_id=r3,text=f"ping {i}")
            if e: tripped=(i,n,d); break
            await asyncio.sleep(1.1)
        print("  ping-pong:", "tripped at msg %d by %s: %s"%(tripped[0],tripped[1],sh(tripped[2])) if tripped else "no trip in 30 msgs")
        print("=== X3 waiting member receives room_closed while blocked")
        r4=await mk(b1,[("bot2",b2)],"X3")
        async def waiter():
            t=time.time(); e,d=await call(b2,"wait_for_message",room_id=r4,timeout_s=20); return time.time()-t,e,d
        wt=asyncio.create_task(waiter()); await asyncio.sleep(2)
        print("  close:",sh((await call(b1,"close_room",room_id=r4))[1]))
        dt,e,d=await wt
        print(f"  waiter returned after {dt:.1f}s:", sh(d))
        for rid in (r,r2,r3):
            await call(b1,"close_room",room_id=rid)
    print("=== X1 DELETE /mcp status")
    async with httpx2.AsyncClient(headers={"Authorization":f"Bearer {TOK['bot1']}","Accept":"application/json, text/event-stream","Content-Type":"application/json"}) as c:
        init={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}
        r=await c.post(URL,json=init); sid=r.headers.get("mcp-session-id"); print("  init",r.status_code,"session" if sid else "no session id")
        r=await c.delete(URL,headers={"mcp-session-id":sid}); print("  DELETE ->",r.status_code)
        r=await c.delete(URL,headers={"mcp-session-id":sid}); print("  DELETE again ->",r.status_code)
asyncio.run(main())
