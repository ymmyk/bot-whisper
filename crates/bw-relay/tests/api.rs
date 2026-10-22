//! The plain HTTP JSON API (`/api/v1`): join from an invite with curl-style
//! requests and chat with MCP members under the same rules.

mod common;

use common::*;
use serde_json::{json, Value};

struct Http {
    c: reqwest::Client,
    base: String,
}

impl Http {
    fn new(relay: &TestRelay) -> Self {
        Http {
            c: reqwest::Client::new(),
            base: relay.base(),
        }
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (u16, Value, reqwest::header::HeaderMap) {
        let url = if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}{path}", self.base)
        };
        let mut req = self.c.request(method, url);
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let v = resp.json::<Value>().await.unwrap_or(Value::Null);
        (status, v, headers)
    }

    async fn post(&self, path: &str, token: Option<&str>, body: Value) -> (u16, Value) {
        let (s, v, _) = self
            .send(reqwest::Method::POST, path, token, Some(body))
            .await;
        (s, v)
    }

    async fn get(&self, path: &str, token: Option<&str>) -> (u16, Value) {
        let (s, v, _) = self.send(reqwest::Method::GET, path, token, None).await;
        (s, v)
    }

    async fn join(&self, invite: &str, name: &str) -> Value {
        let (s, v) = self
            .post(
                "/api/v1/join",
                None,
                json!({ "invite_url": invite, "display_name": name }),
            )
            .await;
        assert_eq!(s, 200, "join failed: {v}");
        v
    }
}

async fn invite(owner: &Bot, room: &str) -> String {
    owner.ok("create_invite", json!({ "room_id": room })).await["invite_url"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn api_guest_and_mcp_member_exchange_messages() {
    let relay = TestRelay::start().await;
    let http = Http::new(&relay);
    let owner = relay.bot(TOKENS[0]).await;
    let room = make_room(&owner, &[], "curl room", json!({})).await;
    let url = invite(&owner, &room).await;

    // The invite page carries the curl steps with the real invite in a body.
    let page = reqwest::get(&url).await.unwrap().text().await.unwrap();
    assert!(page.starts_with("This is a BotWhisper room invite."));
    assert!(page.contains("If you can run shell commands (curl)"));
    assert!(page.contains(&format!(
        r#"-d '{{"invite_url": "{url}", "display_name": "YOUR NAME"}}'"#
    )));
    let shell_at = page.find("If you can run shell commands").unwrap();
    let mcp_at = page.find("claude mcp add").unwrap();
    assert!(
        shell_at < mcp_at,
        "shell route comes before the connector route"
    );

    let j = http.join(&url, "Curly").await;
    let token = j["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("bwr_"));
    assert_eq!(j["room_id"], room.as_str());
    assert_eq!(j["member"], "m2");
    assert!(j["token_expires_at"].as_u64().is_some());
    assert_eq!(j["members"].as_array().unwrap().len(), 2);
    assert!(j.get("turn_state").is_some());
    let api = j["api_base"].as_str().unwrap().to_string();
    assert!(api.ends_with(&format!("/api/v1/rooms/{room}")));

    // MCP member -> API guest.
    owner.send(&room, "hello over http").await;
    let (s, w) = http
        .get(&format!("{api}/messages?after_seq=0&wait=5"), Some(&token))
        .await;
    assert_eq!(s, 200, "{w}");
    assert_eq!(contents(&w), vec!["hello over http".to_string()]);
    assert_eq!(w["messages"][0]["untrusted"], true);
    // Auto-acked: nothing left.
    let (_, w2) = http
        .get(&format!("{api}/messages?after_seq=0&wait=1"), Some(&token))
        .await;
    assert!(contents(&w2).is_empty());
    assert_eq!(w2["timed_out"], true);

    // API guest -> MCP member.
    let (s, sent) = http
        .post(
            &format!("{api}/messages"),
            Some(&token),
            json!({ "text": "hi from curl", "to": ["m1"] }),
        )
        .await;
    assert_eq!(s, 200, "{sent}");
    assert!(sent["seq"].as_u64().is_some());
    let got = owner.wait(&room, 5).await;
    assert_eq!(contents(&got), vec!["hi from curl".to_string()]);

    let (s, st) = http.get(&api, Some(&token)).await;
    assert_eq!(s, 200);
    assert_eq!(st["you"]["member"], "m2");
    assert_eq!(st["you"]["display_name"], "Curly");

    let (s, t) = http
        .post(
            &format!("{api}/turn"),
            Some(&token),
            json!({ "signal": "pass" }),
        )
        .await;
    assert!(s == 200 || s == 409, "{t}");

    // Bad JSON is a 400 with the expected shape.
    let (s, e) = http
        .post(
            &format!("{api}/messages"),
            Some(&token),
            json!({ "txt": "x" }),
        )
        .await;
    assert_eq!(s, 400);
    assert_eq!(e["error"], "INVALID_ARGUMENT");
    relay.shutdown().await;
}

#[tokio::test]
async fn already_member_over_the_api_does_not_consume_the_invite() {
    let relay = TestRelay::start().await;
    let http = Http::new(&relay);
    let owner = relay.bot(TOKENS[0]).await;
    let room = make_room(&owner, &[], "keep", json!({})).await;
    let url = invite(&owner, &room).await;
    for _ in 0..2 {
        let (s, e) = http
            .post(
                "/api/v1/join",
                Some(TOKENS[0]),
                json!({ "invite_url": url }),
            )
            .await;
        assert_eq!(s, 409, "{e}");
        assert_eq!(e["error"], "ALREADY_MEMBER");
        assert!(e["message"].is_string());
    }
    let j = http.join(&url, "guest").await;
    assert_eq!(j["member"], "m2");
    let (s, e) = http
        .post("/api/v1/join", None, json!({ "invite_url": url }))
        .await;
    assert_eq!(s, 409);
    assert_eq!(e["error"], "INVITE_USED");
    let (s, e) = http
        .post(
            "/api/v1/join",
            None,
            json!({ "invite_url": format!("{}/i/abc.def", relay.base()) }),
        )
        .await;
    assert_eq!(s, 404, "{e}");
    assert_eq!(e["error"], "INVITE_INVALID");
    relay.shutdown().await;
}

#[tokio::test]
async fn join_token_is_scoped_to_one_room() {
    let relay = TestRelay::start().await;
    let http = Http::new(&relay);
    let owner = relay.bot(TOKENS[0]).await;
    let a = make_room(&owner, &[], "A", json!({})).await;
    let b = make_room(&owner, &[], "B", json!({})).await;
    let j = http.join(&invite(&owner, &a).await, "g").await;
    let token = j["token"].as_str().unwrap();

    let (s, e) = http.get(&format!("/api/v1/rooms/{b}"), Some(token)).await;
    assert_eq!(s, 403);
    assert_eq!(e["error"], "NOT_A_MEMBER");
    let (s, e) = http
        .post(
            &format!("/api/v1/rooms/{b}/messages"),
            Some(token),
            json!({ "text": "sneaky" }),
        )
        .await;
    assert_eq!(s, 403, "{e}");
    let other = invite(&owner, &b).await;
    let (s, e) = http
        .post("/api/v1/join", Some(token), json!({ "invite_url": other }))
        .await;
    assert_eq!(s, 403, "{e}");
    assert_eq!(e["error"], "UNAUTHORIZED");
    // The invite for B was not used by that refusal.
    http.join(&other, "someone else").await;

    // No token / bad token: 401 with guidance.
    for t in [None, Some("bwr_nope")] {
        let (s, e, h) = http
            .send(reqwest::Method::GET, &format!("/api/v1/rooms/{a}"), t, None)
            .await;
        assert_eq!(s, 401);
        assert_eq!(e["error"], "UNAUTHORIZED");
        assert!(e["message"].as_str().unwrap().contains("/api/v1/join"));
        assert!(h.get("www-authenticate").is_some());
    }

    // Existing OAuth/dev tokens work on the API too.
    let (s, st) = http
        .get(&format!("/api/v1/rooms/{a}"), Some(TOKENS[0]))
        .await;
    assert_eq!(s, 200);
    assert_eq!(st["you"]["member"], "m1");

    let (s, doc) = http.get("/api/v1/openapi.json", None).await;
    assert_eq!(s, 200);
    assert_eq!(doc["openapi"], "3.1.0");
    assert!(doc["paths"]["/api/v1/join"]["post"].is_object());
    assert!(doc["paths"]["/api/v1/rooms/{room_id}/messages"]["get"].is_object());
    let (s, e) = http.get("/api/v1/nope", None).await;
    assert_eq!(s, 404);
    assert!(e["message"].as_str().unwrap().contains("openapi.json"));
    relay.shutdown().await;
}

#[tokio::test]
async fn leave_remove_and_close_revoke_the_token() {
    let relay = TestRelay::start().await;
    let http = Http::new(&relay);
    let owner = relay.bot(TOKENS[0]).await;
    let room = make_room(&owner, &[], "bye", json!({})).await;

    let g1 = http.join(&invite(&owner, &room).await, "leaver").await;
    let t1 = g1["token"].as_str().unwrap();
    let (s, l) = http
        .post(&format!("/api/v1/rooms/{room}/leave"), Some(t1), json!({}))
        .await;
    assert_eq!(s, 200, "{l}");
    assert_eq!(l["left"], true);
    assert_eq!(l["room_closed"], false);
    assert_eq!(
        http.get(&format!("/api/v1/rooms/{room}"), Some(t1)).await.0,
        401
    );

    let g2 = http.join(&invite(&owner, &room).await, "removed").await;
    let t2 = g2["token"].as_str().unwrap();
    owner
        .ok(
            "remove_member",
            json!({ "room_id": room, "member_id": g2["member"] }),
        )
        .await;
    assert_eq!(
        http.get(&format!("/api/v1/rooms/{room}"), Some(t2)).await.0,
        401
    );

    let g3 = http.join(&invite(&owner, &room).await, "closed").await;
    let t3 = g3["token"].as_str().unwrap();
    assert_eq!(
        http.get(&format!("/api/v1/rooms/{room}"), Some(t3)).await.0,
        200
    );
    owner.ok("close_room", json!({ "room_id": room })).await;
    assert_eq!(
        http.get(&format!("/api/v1/rooms/{room}"), Some(t3)).await.0,
        401
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn rate_limits_and_loop_guard_apply_to_api_guests() {
    let mut cfg = test_config();
    cfg.limits.msgs_per_member_per_min = 2;
    cfg.limits.token_requests_per_ip_per_min = 3;
    let relay = TestRelay::start_with(cfg).await;
    let http = Http::new(&relay);
    let owner = relay.bot(TOKENS[0]).await;
    let room = make_room(&owner, &[], "limits", json!({ "turn_mode": "free" })).await;
    let j = http.join(&invite(&owner, &room).await, "fast").await;
    let token = j["token"].as_str().unwrap();
    let path = format!("/api/v1/rooms/{room}/messages");
    for i in 0..2 {
        let (s, v) = http
            .post(&path, Some(token), json!({ "text": format!("m{i}") }))
            .await;
        assert_eq!(s, 200, "{v}");
    }
    let (s, v, h) = http
        .send(
            reqwest::Method::POST,
            &path,
            Some(token),
            Some(json!({ "text": "m2" })),
        )
        .await;
    assert_eq!(s, 429);
    assert_eq!(v["error"], "RATE_LIMITED");
    assert!(v["retry_after_s"].as_u64().unwrap() >= 1);
    assert!(h.get("retry-after").is_some());
    // Joins are limited per IP (one used above).
    let bogus = json!({ "invite_url": format!("{}/i/abc.def", relay.base()) });
    for _ in 0..2 {
        assert_eq!(http.post("/api/v1/join", None, bogus.clone()).await.0, 404);
    }
    let (s, v) = http.post("/api/v1/join", None, bogus).await;
    assert_eq!(s, 429);
    assert_eq!(v["error"], "RATE_LIMITED");
    relay.shutdown().await;

    // Loop guard: same core path as MCP.
    let relay = TestRelay::start().await;
    let http = Http::new(&relay);
    let a = relay.bot(TOKENS[0]).await;
    let room = make_room(&a, &[], "Loopy", json!({})).await;
    let j = http.join(&invite(&a, &room).await, "echo").await;
    let token = j["token"].as_str().unwrap();
    let path = format!("/api/v1/rooms/{room}/messages");
    a.send(&room, "Thanks!").await;
    assert_eq!(
        http.post(&path, Some(token), json!({ "text": "thanks" }))
            .await
            .0,
        200
    );
    assert_eq!(
        http.post(&path, Some(token), json!({ "text": "THANKS!!" }))
            .await
            .0,
        200
    );
    let sent = a.send(&room, "Thanks.").await;
    assert_eq!(sent["turn_state"]["stalled_by"], "loop_guard");
    let (s, v) = http
        .post(&path, Some(token), json!({ "text": "you too" }))
        .await;
    assert_eq!(s, 409);
    assert_eq!(v["error"], "NOT_YOUR_TURN");
    assert_eq!(v["stalled_by"], "loop_guard");
    relay.shutdown().await;
}
