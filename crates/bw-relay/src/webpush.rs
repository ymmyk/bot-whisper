//! Web Push: RFC 8291 payload encryption (`aes128gcm`, RFC 8188 framing) and
//! RFC 8292 VAPID, implemented on RustCrypto (`p256`, `hkdf`, `aes-gcm`).
//!
//! The relay only ever encrypts the content-free `DoorbellPayload`; the
//! subscriber's keys (`p256dh`, `auth`) come from a browser `PushSubscription`
//! or a UnifiedPush distributor. The VAPID private key lives in a 0600 file
//! next to the SQLite database and is never logged.

use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use hkdf::Hkdf;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use rand::RngCore;
use sha2::Sha256;

/// Record size we advertise (one record per message, RFC 8291 §4).
const RS: u32 = 4096;
/// Pad the plaintext to a multiple of this many bytes (traffic analysis).
pub const PAD_TO: usize = 128;

/// The relay's VAPID keypair.
#[derive(Clone)]
pub struct VapidKeys {
    secret: SecretKey,
}

impl std::fmt::Debug for VapidKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VapidKeys")
    }
}

/// 32 random bytes that form a valid P-256 scalar.
fn random_secret() -> SecretKey {
    loop {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        if let Ok(k) = SecretKey::from_slice(&bytes) {
            return k;
        }
    }
}

impl VapidKeys {
    pub fn generate() -> Self {
        VapidKeys {
            secret: random_secret(),
        }
    }

    /// From the hex-encoded 32-byte private scalar.
    pub fn from_hex(hex_scalar: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_scalar.trim()).map_err(|_| "vapid key is not hex")?;
        let secret =
            SecretKey::from_slice(&bytes).map_err(|_| "vapid key is not a P-256 scalar")?;
        Ok(VapidKeys { secret })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.secret.to_bytes())
    }

    /// Uncompressed public point, base64url (what `applicationServerKey` wants).
    pub fn public_key_b64url(&self) -> String {
        B64.encode(self.secret.public_key().to_encoded_point(false).as_bytes())
    }

    /// Load the key from `path`, or generate one and write it (0600 on unix).
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_hex(&s)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                let keys = Self::generate();
                write_private(path, keys.to_hex().as_bytes())?;
                Ok(keys)
            }
            Err(e) => Err(e),
        }
    }

    /// `Authorization: vapid t=<JWT>,k=<public key>` for a push service
    /// origin (RFC 8292 §3). `exp` is `now + 12 h` (the maximum is 24 h).
    pub fn authorization(&self, audience: &str, subject: &str, now: u64) -> String {
        let header = B64.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = serde_json::json!({
            "aud": audience,
            "exp": now + 12 * 3600,
            "sub": subject,
        });
        let claims = B64.encode(serde_json::to_vec(&claims).expect("json"));
        let signing_input = format!("{header}.{claims}");
        let signer = SigningKey::from(&self.secret);
        let sig: Signature = signer.sign(signing_input.as_bytes());
        let jwt = format!("{signing_input}.{}", B64.encode(sig.to_bytes()));
        format!("vapid t={jwt},k={}", self.public_key_b64url())
    }
}

/// Write a secret file, readable by the owner only on unix.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

/// The subscriber's half of a Web Push subscription.
#[derive(Debug, Clone)]
pub struct Subscriber<'a> {
    /// `p256dh`: uncompressed P-256 point, base64url.
    pub p256dh: &'a str,
    /// `auth`: 16-byte secret, base64url.
    pub auth: &'a str,
}

fn decode(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim().trim_end_matches('='))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s.trim()))
        .map_err(|_| "invalid base64url".to_string())
}

/// Validate subscriber keys (65-byte uncompressed point, 16-byte auth).
pub fn validate_subscriber(p256dh: &str, auth: &str) -> Result<(), String> {
    let p = decode(p256dh)?;
    PublicKey::from_sec1_bytes(&p).map_err(|_| "p256dh is not a P-256 public key")?;
    if p.len() != 65 {
        return Err("p256dh must be an uncompressed P-256 point".into());
    }
    if decode(auth)?.len() != 16 {
        return Err("auth must be 16 bytes".into());
    }
    Ok(())
}

/// RFC 8291 key derivation shared by both ends.
fn derive(
    ecdh_secret: &[u8],
    auth_secret: &[u8],
    ua_public: &[u8],
    as_public: &[u8],
    salt: &[u8; 16],
) -> ([u8; 16], [u8; 12]) {
    // IKM = HKDF(auth_secret, ecdh_secret, "WebPush: info" || 0 || ua || as, 32)
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(auth_secret), ecdh_secret)
        .expand(&key_info, &mut ikm)
        .expect("32 bytes");
    let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut cek = [0u8; 16];
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .expect("16 bytes");
    let mut nonce = [0u8; 12];
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
        .expect("12 bytes");
    (cek, nonce)
}

/// Encrypt `plaintext` for a subscriber. Returns the full `aes128gcm` body
/// (header + one record). `salt` and `as_secret` are random unless given
/// (tests pass the RFC 8291 Appendix A values). `pad_to` is the multiple
/// the padded record is rounded up to (`0` for none).
pub fn encrypt(
    sub: &Subscriber<'_>,
    plaintext: &[u8],
    salt: Option<[u8; 16]>,
    as_secret: Option<SecretKey>,
    pad_to: usize,
) -> Result<Vec<u8>, String> {
    let ua_public_bytes = decode(sub.p256dh)?;
    let ua_public =
        PublicKey::from_sec1_bytes(&ua_public_bytes).map_err(|_| "bad p256dh".to_string())?;
    let auth = decode(sub.auth)?;
    let salt = salt.unwrap_or_else(|| {
        let mut s = [0u8; 16];
        rand::rng().fill_bytes(&mut s);
        s
    });
    let as_secret = as_secret.unwrap_or_else(random_secret);
    let as_public = as_secret.public_key().to_encoded_point(false);
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_public.as_affine());
    let (cek, nonce) = derive(
        shared.raw_secret_bytes(),
        &auth,
        &ua_public_bytes,
        as_public.as_bytes(),
        &salt,
    );

    // Padded record: plaintext || 0x02 || zeros (RFC 8188 §2).
    let mut record = plaintext.to_vec();
    record.push(2);
    if pad_to > 0 {
        let want = record.len().div_ceil(pad_to) * pad_to;
        record.resize(want, 0);
    }
    if record.len() + 16 > RS as usize {
        return Err("payload too large for one record".into());
    }
    let cipher = Aes128Gcm::new((&cek).into());
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &record,
                aad: &[],
            },
        )
        .map_err(|_| "aes-gcm failure".to_string())?;

    // Header: salt(16) | rs(4) | idlen(1) | keyid (the as_public point).
    let mut out = Vec::with_capacity(21 + 65 + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&RS.to_be_bytes());
    out.push(as_public.as_bytes().len() as u8);
    out.extend_from_slice(as_public.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt an `aes128gcm` body with the subscriber's private key (tests and
/// client-side verification; the relay never calls this).
pub fn decrypt(ua_secret: &SecretKey, auth_b64: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    if body.len() < 21 {
        return Err("body too short".into());
    }
    let salt: [u8; 16] = body[..16].try_into().expect("16");
    let idlen = body[20] as usize;
    let keyid = &body[21..21 + idlen];
    let ct = &body[21 + idlen..];
    let as_public = PublicKey::from_sec1_bytes(keyid).map_err(|_| "bad keyid".to_string())?;
    let ua_public = ua_secret.public_key().to_encoded_point(false);
    let auth = decode(auth_b64)?;
    let shared = p256::ecdh::diffie_hellman(ua_secret.to_nonzero_scalar(), as_public.as_affine());
    let (cek, nonce) = derive(
        shared.raw_secret_bytes(),
        &auth,
        ua_public.as_bytes(),
        keyid,
        &salt,
    );
    let cipher = Aes128Gcm::new((&cek).into());
    let mut record = cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad: &[] })
        .map_err(|_| "decrypt failed".to_string())?;
    // Strip padding: trailing zeros, then the 0x02 delimiter.
    while record.last() == Some(&0) {
        record.pop();
    }
    if record.pop() != Some(2) {
        return Err("bad padding delimiter".into());
    }
    Ok(record)
}

/// Verify a `vapid t=..,k=..` header against the public key it carries.
/// Returns the claims when the signature and `aud` check out.
pub fn verify_authorization(header: &str, audience: &str) -> Result<serde_json::Value, String> {
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    let rest = header.strip_prefix("vapid ").ok_or("not a vapid header")?;
    let mut t = None;
    let mut k = None;
    for part in rest.split(',') {
        if let Some(v) = part.trim().strip_prefix("t=") {
            t = Some(v);
        } else if let Some(v) = part.trim().strip_prefix("k=") {
            k = Some(v);
        }
    }
    let (Some(t), Some(k)) = (t, k) else {
        return Err("missing t or k".into());
    };
    let key = VerifyingKey::from_sec1_bytes(&decode(k)?).map_err(|_| "bad k".to_string())?;
    let mut parts = t.split('.');
    let (Some(h), Some(c), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("bad jwt".into());
    };
    let sig = Signature::from_slice(&decode(s)?).map_err(|_| "bad signature".to_string())?;
    key.verify(format!("{h}.{c}").as_bytes(), &sig)
        .map_err(|_| "signature does not verify".to_string())?;
    let header: serde_json::Value =
        serde_json::from_slice(&decode(h)?).map_err(|_| "bad header".to_string())?;
    if header["alg"] != "ES256" {
        return Err("alg is not ES256".into());
    }
    let claims: serde_json::Value =
        serde_json::from_slice(&decode(c)?).map_err(|_| "bad claims".to_string())?;
    if claims["aud"] != audience {
        return Err(format!("aud {} != {audience}", claims["aud"]));
    }
    Ok(claims)
}

/// `scheme://host[:port]` of a push endpoint (the VAPID audience).
pub fn origin_of(endpoint: &str) -> Result<String, String> {
    let u = reqwest::Url::parse(endpoint).map_err(|e| e.to_string())?;
    let host = u.host_str().ok_or("endpoint has no host")?;
    Ok(match u.port() {
        Some(p) => format!("{}://{host}:{p}", u.scheme()),
        None => format!("{}://{host}", u.scheme()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    const UA_PUBLIC: &str =
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const UA_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
    const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
    /// The 86-octet header and the ciphertext, as Appendix A lists them.
    const HEADER: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    const CIPHERTEXT: &str =
        "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ";

    #[test]
    fn rfc8291_appendix_a_vector() {
        let as_secret = SecretKey::from_slice(&decode(AS_PRIVATE).unwrap()).unwrap();
        let salt: [u8; 16] = decode(SALT).unwrap().try_into().unwrap();
        let body = encrypt(
            &Subscriber {
                p256dh: UA_PUBLIC,
                auth: AUTH,
            },
            b"When I grow up, I want to be a watermelon",
            Some(salt),
            Some(as_secret),
            0,
        )
        .unwrap();
        let mut expected = decode(HEADER).unwrap();
        expected.extend(decode(CIPHERTEXT).unwrap());
        assert_eq!(body, expected);
        let ua = SecretKey::from_slice(&decode(UA_PRIVATE).unwrap()).unwrap();
        assert_eq!(
            decrypt(&ua, AUTH, &body).unwrap(),
            b"When I grow up, I want to be a watermelon"
        );
    }

    #[test]
    fn round_trip_with_padding_and_fresh_keys() {
        let ua = random_secret();
        let p256dh = B64.encode(ua.public_key().to_encoded_point(false).as_bytes());
        let mut auth = [0u8; 16];
        rand::rng().fill_bytes(&mut auth);
        let auth = B64.encode(auth);
        validate_subscriber(&p256dh, &auth).unwrap();
        let msg = br#"{"v":1,"event":"message","room":"r","seq":3,"turn":"open","ts":1}"#;
        let body = encrypt(
            &Subscriber {
                p256dh: &p256dh,
                auth: &auth,
            },
            msg,
            None,
            None,
            PAD_TO,
        )
        .unwrap();
        assert_eq!(decrypt(&ua, &auth, &body).unwrap(), msg);
        assert!(validate_subscriber("AAAA", &auth).is_err());
        assert!(validate_subscriber(&p256dh, "short").is_err());
    }

    #[test]
    fn vapid_header_verifies_and_key_file_round_trips() {
        let keys = VapidKeys::generate();
        let h = keys.authorization("https://push.example", "mailto:a@b.c", 1_000);
        let claims = verify_authorization(&h, "https://push.example").unwrap();
        assert_eq!(claims["sub"], "mailto:a@b.c");
        assert_eq!(claims["exp"], 1_000 + 12 * 3600);
        assert!(verify_authorization(&h, "https://other.example").is_err());
        let again = VapidKeys::from_hex(&keys.to_hex()).unwrap();
        assert_eq!(again.public_key_b64url(), keys.public_key_b64url());
        let dir = std::env::temp_dir().join(format!("bw-vapid-{}", uuid::Uuid::new_v4()));
        let path = dir.join("vapid.key");
        let a = VapidKeys::load_or_create(&path).unwrap();
        let b = VapidKeys::load_or_create(&path).unwrap();
        assert_eq!(a.public_key_b64url(), b.public_key_b64url());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(dir);
        assert_eq!(
            origin_of("https://fcm.googleapis.com/fcm/send/abc").unwrap(),
            "https://fcm.googleapis.com"
        );
    }
}
