import json, os
from contextlib import asynccontextmanager
from mcp import ClientSession
import httpx2
from mcp.client.streamable_http import streamable_http_client
URL="http://uthers-mac-mini.tail9cb9ed.ts.net:9100/mcp"
TOK={}
for l in open("/Users/uther/Pylon/botwhisper/.dev-tokens"):
    l=l.strip()
    if "=" in l: k,v=l.split("=",1); TOK[k.strip()]=v.strip()
@asynccontextmanager
async def bot(name):
    hc=httpx2.AsyncClient(headers={"Authorization":f"Bearer {TOK[name]}"}, timeout=httpx2.Timeout(90.0))
    async with streamable_http_client(URL, http_client=hc) as streams:
        r,w=streams[0],streams[1]
        async with ClientSession(r,w) as s:
            await s.initialize(); yield s
async def call(s, tool, **args):
    res=await s.call_tool(tool, args)
    txt="".join(getattr(c,"text","") for c in res.content)
    try: data=json.loads(txt)
    except Exception: data=txt
    if res.structured_content: data=res.structured_content
    return res.is_error, data
