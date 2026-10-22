import asyncio, json, re, urllib.parse as up, httpx2
from common import bot, call
B="http://uthers-mac-mini.tail9cb9ed.ts.net:9100"
import os, secrets, hashlib, base64
B=os.environ.get("BW_BASE",B)
RED="http://127.0.0.1:9199/cb"
CID=httpx2.post(B+"/oauth/register",json={"client_name":"mcp_client oauth test","redirect_uris":[RED],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}).json()["client_id"]
V=secrets.token_urlsafe(48); CH=base64.urlsafe_b64encode(hashlib.sha256(V.encode()).digest()).rstrip(b"=").decode()
def red(t): return re.sub(r'(token"?\s*[:=]\s*"?)[A-Za-z0-9_\-\.]{12,}', r'\1***', t)
async def whoami(tok):
    async with httpx2.AsyncClient(headers={"Authorization":f"Bearer {tok}","Accept":"application/json, text/event-stream"}) as c:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        async with streamable_http_client(B+"/mcp", http_client=c) as st:
            async with ClientSession(st[0],st[1]) as s:
                await s.initialize(); return await call(s,"list_rooms")
async def main():
    async with bot("bot1") as b1:
        _,d=await call(b1,"create_room",title="OAuth",display_name="bot1"); rid=d["room_id"]
        async with httpx2.AsyncClient(follow_redirects=False) as c:
          async def getcode(lbl):
            _,inv=await call(b1,"create_invite",room_id=rid,label=lbl)
            form=dict(client_id=CID,redirect_uri=RED,code_challenge=CH,code_challenge_method="S256",response_type="code",state="xyz",scope="rooms",action="invite",invite_url=inv["invite_url"],display_name=lbl)
            r=await c.post(B+"/oauth/authorize",data=form); loc=r.headers.get("location","")
            print("authorize POST",r.status_code,"redirect host ok" if loc.startswith(RED) else red(r.text[:400]))
            q=dict(up.parse_qsl(up.urlparse(loc).query)); print("  state echoed:",q.get("state")=="xyz","code present:",bool(q.get("code")))
            return q["code"]
          if True:
            bad=await getcode("badpkce")
            r=await c.post(B+"/oauth/token",data=dict(grant_type="authorization_code",code=bad,redirect_uri=RED,client_id=CID,code_verifier="wrong"+V[5:]))
            print("token w/ bad verifier:",r.status_code,r.text[:120])
            code=await getcode("oauth-guest")
            r=await c.post(B+"/oauth/token",data=dict(grant_type="authorization_code",code=code,redirect_uri=RED,client_id=CID,code_verifier=V))
            t1=r.json(); print("token:",r.status_code,{k:("***" if "token" in k else v) for k,v in t1.items()})
            r=await c.post(B+"/oauth/token",data=dict(grant_type="authorization_code",code=code,redirect_uri=RED,client_id=CID,code_verifier=V))
            print("code reuse:",r.status_code,r.text[:120])
            e,w1=await whoami(t1["access_token"]); print("access1 list_rooms:",e,json.dumps(w1)[:300])
            r=await c.post(B+"/oauth/token",data=dict(grant_type="refresh_token",refresh_token=t1["refresh_token"],client_id=CID))
            t2=r.json(); print("refresh:",r.status_code,{k:("***" if "token" in k else v) for k,v in t2.items()}, "rotated:",t2.get("refresh_token")!=t1["refresh_token"])
            e,w2=await whoami(t2["access_token"]); print("access2 list_rooms:",e,json.dumps(w2)[:300])
            m1=[x["member_id"] for x in w1["rooms"]]; m2=[x["member_id"] for x in w2["rooms"]]
            print("same member:", m1==m2 and bool(m1), m1, m2)
            r=await c.post(B+"/oauth/token",data=dict(grant_type="refresh_token",refresh_token=t1["refresh_token"],client_id=CID))
            print("old refresh reuse:",r.status_code,r.text[:160])
            r=await c.post(B+"/oauth/token",data=dict(grant_type="refresh_token",refresh_token=t2["refresh_token"],client_id=CID))
            print("new refresh after old-reuse (family revoked?):",r.status_code,"revoked" if r.status_code!=200 else "still valid")
            # Reuse of t1's refresh token revokes the whole grant chain, so both
            # access tokens must now be refused.
            for lbl,tok in (("new access after old-reuse",t2["access_token"]),("old access after old-reuse",t1["access_token"])):
                try:
                    e,w=await asyncio.wait_for(whoami(tok),30); print(lbl+": STILL VALID",e,json.dumps(w)[:150])
                except Exception as ex: print(lbl+": rejected",type(ex).__name__)
        await call(b1,"close_room",room_id=rid)
asyncio.run(main())
