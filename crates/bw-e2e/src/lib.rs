//! End-to-end encryption for BotWhisper rooms: a thin wrapper over OpenMLS
//! (RFC 9420). See `docs/design/e2e-rooms.md`.
//!
//! One [`Identity`] per bot (Ed25519 signature keypair + `BasicCredential`
//! whose identity is the bot's relay agent id, plus the OpenMLS provider that
//! holds its private key material). A room is a [`Group`]. Everything that
//! crosses the relay is an opaque TLS-serialized `MlsMessage` byte string:
//! key packages, commits, Welcomes and application ciphertext.
//!
//! Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, fixed.

use openmls::prelude::{tls_codec::Deserialize as _, tls_codec::Serialize as _, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;
use sha2::{Digest, Sha256};

/// The one ciphersuite BotWhisper uses.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Debug, thiserror::Error)]
pub enum E2eError {
    #[error("mls: {0}")]
    Mls(String),
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("identity file: {0}")]
    Identity(String),
    #[error("unknown member {0}")]
    UnknownMember(String),
}

type Result<T> = std::result::Result<T, E2eError>;

fn mls<E: std::fmt::Display>(e: E) -> E2eError {
    E2eError::Mls(e.to_string())
}

/// A bot's long-lived MLS identity and key store.
pub struct Identity {
    agent_id: String,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    provider: OpenMlsRustCrypto,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("agent_id", &self.agent_id)
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

/// On-disk form of an identity (secret: write it 0600).
#[derive(serde::Serialize, serde::Deserialize)]
struct IdentityFile {
    v: u16,
    agent_id: String,
    /// The Ed25519 keypair (private key included) in the crate's own serde
    /// form.
    signer: SignatureKeyPair,
}

impl Identity {
    /// A fresh identity for a bot. `agent_id` is the relay's stable agent id
    /// (`<account>:<bot>`), which becomes the credential identity.
    pub fn new(agent_id: &str) -> Result<Self> {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).map_err(mls)?;
        Self::from_signer(agent_id, signer)
    }

    fn from_signer(agent_id: &str, signer: SignatureKeyPair) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        signer.store(provider.storage()).map_err(mls)?;
        let credential: Credential = BasicCredential::new(agent_id.as_bytes().to_vec()).into();
        let credential = CredentialWithKey {
            credential,
            signature_key: signer.public().into(),
        };
        Ok(Identity {
            agent_id: agent_id.to_string(),
            signer,
            credential,
            provider,
        })
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// SHA-256 of the public signature key, hex. Goes into invite fragments
    /// (`f=`) so a joiner can verify who sent its Welcome.
    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.signer.public()))
    }

    /// Serialize for the config directory (contains the private key).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&IdentityFile {
            v: 1,
            agent_id: self.agent_id.clone(),
            signer: SignatureKeyPair::from_raw(
                self.signer.signature_scheme(),
                private_key_of(&self.signer),
                self.signer.to_public_vec(),
            ),
        })
        .expect("json")
    }

    /// Load from `to_bytes` output. Group state is not included: in M1 the
    /// connector keeps groups for the life of the process (M2: SQLite).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let f: IdentityFile =
            serde_json::from_slice(bytes).map_err(|e| E2eError::Identity(e.to_string()))?;
        if f.v != 1 || f.signer.signature_scheme() != SignatureScheme::ED25519 {
            return Err(E2eError::Identity("unsupported identity file".into()));
        }
        Self::from_signer(&f.agent_id, f.signer)
    }

    /// A fresh one-time key package, serialized for `e2e_publish_key_packages`.
    pub fn key_package(&self) -> Result<Vec<u8>> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(mls)?;
        MlsMessageOut::from(bundle.key_package().clone())
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// Create a new group for a room (the creator is its only member).
    pub fn create_group(&self, room_id: &str) -> Result<Group> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(room_id.as_bytes()),
            self.credential.clone(),
        )
        .map_err(mls)?;
        Ok(Group { group })
    }

    /// Join a group from a serialized Welcome addressed to one of our key
    /// packages. Returns the group and the inviter (credential identity and
    /// signature-key fingerprint, to check against an invite's `f=`).
    pub fn join(&self, welcome: &[u8]) -> Result<(Group, Inviter)> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|e| E2eError::Malformed(e.to_string()))?;
        let MlsMessageBodyIn::Welcome(welcome) = msg.extract() else {
            return Err(E2eError::Malformed("not a Welcome".into()));
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged =
            StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None).map_err(mls)?;
        let sender = staged.welcome_sender().map_err(mls)?;
        let inviter = Inviter {
            agent_id: identity_of(sender.credential()),
            fingerprint: hex::encode(Sha256::digest(sender.signature_key().as_slice())),
        };
        let group = staged.into_group(&self.provider).map_err(mls)?;
        Ok((Group { group }, inviter))
    }
}

/// The private half of a keypair. The crate only exposes it through serde,
/// so round-trip through its own JSON form.
fn private_key_of(signer: &SignatureKeyPair) -> Vec<u8> {
    let v = serde_json::to_value(signer).expect("json");
    serde_json::from_value(v["private"].clone()).expect("private key bytes")
}

/// Who sent a Welcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inviter {
    pub agent_id: String,
    /// SHA-256 of the inviter's signature public key, hex (`Identity::fingerprint`).
    pub fingerprint: String,
}

/// Parse a serialized key package (as claimed from the relay).
fn parse_key_package(provider: &OpenMlsRustCrypto, bytes: &[u8]) -> Result<KeyPackage> {
    let msg = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|e| E2eError::Malformed(e.to_string()))?;
    let MlsMessageBodyIn::KeyPackage(kp) = msg.extract() else {
        return Err(E2eError::Malformed("not a key package".into()));
    };
    kp.validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(mls)
}

fn identity_of(credential: &Credential) -> String {
    BasicCredential::try_from(credential.clone())
        .map(|b| String::from_utf8_lossy(b.identity()).to_string())
        .unwrap_or_default()
}

/// What processing an incoming message produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Decrypted application message from the member with this identity.
    Message { sender: String, plaintext: Vec<u8> },
    /// A commit was applied; the group is now at `epoch`.
    Commit { epoch: u64 },
    /// A proposal was queued (BotWhisper does not use standalone proposals).
    Proposal,
    /// Our own message or pending commit came back; nothing to do.
    Own,
}

/// An MLS group for one room.
pub struct Group {
    group: MlsGroup,
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group")
            .field("epoch", &self.epoch())
            .finish()
    }
}

impl Group {
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn room_id(&self) -> String {
        String::from_utf8_lossy(self.group.group_id().as_slice()).to_string()
    }

    /// Credential identities (agent ids) of the current members.
    pub fn members(&self) -> Vec<String> {
        self.group
            .members()
            .map(|m| identity_of(&m.credential))
            .collect()
    }

    /// Add a member from its serialized key package. Returns the serialized
    /// commit (for every current member) and Welcome (for the newcomer), and
    /// advances our epoch.
    pub fn add_member(&mut self, me: &Identity, key_package: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let kp = parse_key_package(&me.provider, key_package)?;
        let (commit, welcome, _info) = self
            .group
            .add_members(&me.provider, &me.signer, &[kp])
            .map_err(mls)?;
        self.group.merge_pending_commit(&me.provider).map_err(mls)?;
        Ok((
            commit.tls_serialize_detached().map_err(mls)?,
            welcome.tls_serialize_detached().map_err(mls)?,
        ))
    }

    /// Remove the member with this credential identity. Returns the commit.
    pub fn remove_member(&mut self, me: &Identity, agent_id: &str) -> Result<Vec<u8>> {
        let idx = self
            .group
            .members()
            .find(|m| identity_of(&m.credential) == agent_id)
            .map(|m| m.index)
            .ok_or_else(|| E2eError::UnknownMember(agent_id.to_string()))?;
        let (commit, _welcome, _info) = self
            .group
            .remove_members(&me.provider, &me.signer, &[idx])
            .map_err(mls)?;
        self.group.merge_pending_commit(&me.provider).map_err(mls)?;
        commit.tls_serialize_detached().map_err(mls)
    }

    /// Encrypt an application message for the group.
    pub fn encrypt(&mut self, me: &Identity, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.group
            .create_message(&me.provider, &me.signer, plaintext)
            .map_err(mls)?
            .tls_serialize_detached()
            .map_err(mls)
    }

    /// Process an incoming commit or application message from the relay.
    pub fn process(&mut self, me: &Identity, bytes: &[u8]) -> Result<Event> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|e| E2eError::Malformed(e.to_string()))?;
        let protocol = msg
            .try_into_protocol_message()
            .map_err(|e| E2eError::Malformed(e.to_string()))?;
        let processed = self
            .group
            .process_message(&me.provider, protocol)
            .map_err(mls)?;
        let sender = identity_of(processed.credential());
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(Event::Message {
                sender,
                plaintext: app.into_bytes(),
            }),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&me.provider, *staged)
                    .map_err(mls)?;
                Ok(Event::Commit {
                    epoch: self.epoch(),
                })
            }
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => Ok(Event::Proposal),
            ProcessedMessageContent::OwnPendingCommit
            | ProcessedMessageContent::OwnPrivateMessage => Ok(Event::Own),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three bots, two of them on the same account: create, add, exchange,
    /// remove one, and the removed bot can no longer read new messages.
    #[test]
    fn three_bots_add_exchange_remove() {
        let alice = Identity::new("acct1:alice").unwrap();
        let bob = Identity::new("acct1:bob").unwrap();
        let carol = Identity::new("acct2:carol").unwrap();
        assert_ne!(alice.fingerprint(), bob.fingerprint(), "per-bot keys");

        let mut g_alice = alice.create_group("room-1").unwrap();
        assert_eq!(g_alice.epoch(), 0);
        assert_eq!(g_alice.members(), vec!["acct1:alice"]);

        // Add Bob: commit (nobody else to deliver it to yet) + Welcome.
        let kp_bob = bob.key_package().unwrap();
        let (_commit1, welcome_bob) = g_alice.add_member(&alice, &kp_bob).unwrap();
        assert_eq!(g_alice.epoch(), 1);
        let (mut g_bob, inviter) = bob.join(&welcome_bob).unwrap();
        assert_eq!(inviter.agent_id, "acct1:alice");
        assert_eq!(inviter.fingerprint, alice.fingerprint());
        assert_eq!(g_bob.epoch(), 1);
        assert_eq!(g_bob.members(), g_alice.members());

        // Add Carol: Bob must process the commit; Carol joins from the Welcome.
        let kp_carol = carol.key_package().unwrap();
        let (commit2, welcome_carol) = g_alice.add_member(&alice, &kp_carol).unwrap();
        assert_eq!(
            g_bob.process(&bob, &commit2).unwrap(),
            Event::Commit { epoch: 2 }
        );
        let (mut g_carol, _) = carol.join(&welcome_carol).unwrap();
        assert_eq!(g_carol.epoch(), 2);
        assert_eq!(g_carol.members().len(), 3);

        // Messages in every direction.
        let ct = g_alice.encrypt(&alice, b"hello from alice").unwrap();
        assert_eq!(
            g_bob.process(&bob, &ct).unwrap(),
            Event::Message {
                sender: "acct1:alice".into(),
                plaintext: b"hello from alice".to_vec()
            }
        );
        assert_eq!(
            g_carol.process(&carol, &ct).unwrap(),
            Event::Message {
                sender: "acct1:alice".into(),
                plaintext: b"hello from alice".to_vec()
            }
        );
        let ct = g_carol.encrypt(&carol, b"carol here").unwrap();
        assert!(
            matches!(g_alice.process(&alice, &ct).unwrap(), Event::Message { ref sender, .. } if sender == "acct2:carol")
        );
        assert!(matches!(
            g_bob.process(&bob, &ct).unwrap(),
            Event::Message { .. }
        ));
        // Ciphertext is not plaintext.
        assert!(!String::from_utf8_lossy(&ct).contains("carol here"));

        // Alice removes Bob; Carol applies the commit; Bob is locked out.
        let commit3 = g_alice.remove_member(&alice, "acct1:bob").unwrap();
        assert_eq!(g_alice.epoch(), 3);
        assert_eq!(
            g_carol.process(&carol, &commit3).unwrap(),
            Event::Commit { epoch: 3 }
        );
        assert_eq!(g_alice.members(), vec!["acct1:alice", "acct2:carol"]);
        let ct = g_alice.encrypt(&alice, b"after the removal").unwrap();
        assert!(
            matches!(g_carol.process(&carol, &ct).unwrap(), Event::Message { ref plaintext, .. } if plaintext == b"after the removal")
        );
        assert!(
            g_bob.process(&bob, &ct).is_err(),
            "the removed bot cannot decrypt the new epoch"
        );
        assert!(g_alice.remove_member(&alice, "acct9:nobody").is_err());
    }

    #[test]
    fn identity_round_trips_through_its_file() {
        let a = Identity::new("acct:bot").unwrap();
        let bytes = a.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("\"private\""));
        let b = Identity::from_bytes(&bytes).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(b.agent_id(), "acct:bot");
        // The restored identity can still be invited (its key packages are
        // fresh) and can read messages. (Adding it to a group its original
        // copy owns would be a duplicate signature key, which MLS refuses.)
        let owner = Identity::new("acct:owner").unwrap();
        let mut g = owner.create_group("r").unwrap();
        let kp = b.key_package().unwrap();
        let (_c, w) = g.add_member(&owner, &kp).unwrap();
        let (mut gb, inviter) = b.join(&w).unwrap();
        assert_eq!(inviter.agent_id, "acct:owner");
        let ct = g.encrypt(&owner, b"x").unwrap();
        assert!(matches!(
            gb.process(&b, &ct).unwrap(),
            Event::Message { .. }
        ));
        assert!(Identity::from_bytes(b"{}").is_err());
    }
}
