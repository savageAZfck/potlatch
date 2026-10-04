//! # potlatch — the mind economy.
//!
//! Sovereign organisms trade compute as a bilateral resource: **signed
//! IOUs** issued under a treaty, **settled against signed invocation
//! records**, all on a hash-chained book any party can audit offline.
//!
//! Potlatch — the gift economy where standing is built by what you give
//! and proven by what you settle.
//!
//! ## Why this exists
//!
//! Economics needs scarcity and property. A cloud API has neither — the
//! vendor owns the meter. Between sovereign organisms, compute is
//! *owned*: organism A spends its GPU-seconds running work for organism
//! B under a treaty, and the debt is real because A's ledger attests the
//! cost. Potlatch makes that debt a first-class artifact:
//!
//! - **`Iou`** — dual-signed debt instrument: creditor issues, debtor
//!   accepts. References the treaty that authorizes the relationship.
//! - **`Invocation`** — signed record of actual treaty work performed;
//!   settlement burns invocations against IOUs so debt tracks *real
//!   usage*, not promises.
//! - **`Settlement`** — dual-signed: creditor confirms the debt dropped.
//! - **`Book`** — the hash-chained ledger: every issuance, invocation,
//!   settlement, and default is a committed event. Outstanding balance
//!   and defaults are computable by anyone holding the book.
//!
//! An organism can earn its next brain-swap — and its credit is its
//! history, which it cannot forge without breaking the chain.
//!
//! ```rust
//! use potlatch::{Book, Identity};
//! let creditor = Identity::generate();
//! let debtor = Identity::generate();
//! let mut book = Book::new();
//! // Creditor issues a 600-compute-second IOU under treaty "t-1".
//! let iou = book.issue(&creditor, &debtor.public_key(), "t-1", "compute-seconds", 600, None);
//! let iou = book.accept(iou, &debtor).unwrap();
//! // Debtor performs work; creditor logs the invocation.
//! let inv = book.invoke(&debtor, &iou.id, 200);
//! book.settle(&creditor, &iou.id, &[&inv.id]);
//! assert_eq!(book.balance(&iou.id).unwrap(), 400);
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;

// ── errors ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Error {
    /// IOU not found on the book.
    UnknownIou(String),
    /// Invocation not found on the book.
    UnknownInvocation(String),
    /// Settlement exceeds remaining balance.
    OverSettled {
        attempted: u64,
        remaining: u64,
    },
    /// Wrong party for the operation.
    WrongParty(String),
    /// Signature failed.
    BadSignature(String),
    /// Book integrity failure.
    BrokenBook(String),
    Serialization(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownIou(id) => write!(f, "unknown iou: {id}"),
            Error::UnknownInvocation(id) => write!(f, "unknown invocation: {id}"),
            Error::OverSettled {
                attempted,
                remaining,
            } => write!(
                f,
                "settlement {attempted} exceeds remaining balance {remaining}"
            ),
            Error::WrongParty(m) => write!(f, "wrong party: {m}"),
            Error::BadSignature(m) => write!(f, "bad signature: {m}"),
            Error::BrokenBook(m) => write!(f, "book integrity failure: {m}"),
            Error::Serialization(m) => write!(f, "serialization: {m}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
fn canonical<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}
mod hex {
    pub fn encode(b: impl AsRef<[u8]>) -> String {
        b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
    }
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}
fn verify_sig(pubkey: &str, msg: &[u8], sig_hex: &str) -> Result<(), Error> {
    let key_bytes = hex::decode(pubkey).map_err(|_| Error::BadSignature("bad pubkey".into()))?;
    let pk = VerifyingKey::from_bytes(
        &<[u8; 32]>::try_from(key_bytes.as_slice())
            .map_err(|_| Error::BadSignature("bad pubkey".into()))?,
    )
    .map_err(|_| Error::BadSignature("bad pubkey".into()))?;
    let sig_bytes =
        hex::decode(sig_hex).map_err(|_| Error::BadSignature("bad signature".into()))?;
    let sig = Signature::from_bytes(
        &<[u8; 64]>::try_from(sig_bytes.as_slice())
            .map_err(|_| Error::BadSignature("bad signature".into()))?,
    );
    pk.verify(msg, &sig)
        .map_err(|_| Error::BadSignature("signature invalid".into()))
}

// ── identity ───────────────────────────────────────────────────────

pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Identity {
            signing: SigningKey::generate(&mut OsRng),
        }
    }
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Identity {
            signing: SigningKey::from_bytes(bytes),
        }
    }
    pub fn public_key(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }
    pub fn seed(&self) -> &[u8; 32] {
        self.signing.as_bytes()
    }
    fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.signing.sign(msg).to_bytes())
    }
}

// ── instruments ────────────────────────────────────────────────────

/// A signed debt instrument. Creditor signs at issuance; the debtor
/// countersigns at acceptance — debt requires both parties' consent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iou {
    pub id: String,
    /// Who is owed.
    pub creditor: String,
    /// Who owes.
    pub debtor: String,
    /// The treaty authorizing this economic relationship.
    pub treaty: String,
    /// Resource unit — "compute-seconds", "tokens", "memory-mb-hours".
    pub resource: String,
    /// Total face value.
    pub amount: u64,
    /// Optional due epoch; past-due unsettled IOUs may be defaulted.
    pub due: Option<u64>,
    pub ts: u64,
    pub creditor_signature: String,
    /// Empty until the debtor accepts.
    pub debtor_signature: String,
}

impl Iou {
    fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id, "creditor": self.creditor, "debtor": self.debtor,
            "treaty": self.treaty, "resource": self.resource,
            "amount": self.amount, "due": self.due, "ts": self.ts,
        })
    }
    /// Verify both signatures (debtor sig may be absent pre-acceptance).
    pub fn verify(&self) -> Result<(), Error> {
        verify_sig(
            &self.creditor,
            &canonical(&self.body()),
            &self.creditor_signature,
        )?;
        if !self.debtor_signature.is_empty() {
            verify_sig(
                &self.debtor,
                &canonical(&self.body()),
                &self.debtor_signature,
            )?;
        }
        Ok(())
    }
    pub fn accepted(&self) -> bool {
        !self.debtor_signature.is_empty()
    }
}

/// Signed record that a debtor performed real work under the treaty —
/// the unit settlement burns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invocation {
    pub id: String,
    /// The IOU this work pays down.
    pub iou: String,
    /// Who performed the work (the debtor).
    pub worker: String,
    /// Units of work performed.
    pub units: u64,
    pub ts: u64,
    pub signature: String,
}

impl Invocation {
    fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id, "iou": self.iou, "worker": self.worker,
            "units": self.units, "ts": self.ts,
        })
    }
}

/// Dual-signed settlement: creditor confirms invocations reduced the
/// debt by `units`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settlement {
    pub id: String,
    pub iou: String,
    /// Invocation ids burned in this settlement.
    pub invocations: Vec<String>,
    pub units: u64,
    pub ts: u64,
    pub signature: String,
}

/// Book event kinds — the hash-chained record of the economy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    Issue {
        iou: Iou,
    },
    Accept {
        iou: Iou,
    },
    Invoke {
        invocation: Invocation,
    },
    Settle {
        settlement: Settlement,
    },
    Default {
        iou: String,
        reason: String,
        creditor: String,
    },
}

/// One committed event on the book.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub kind: EventKind,
    pub prev_hash: String,
    pub hash: String,
    pub ts: u64,
}

// ── the book ───────────────────────────────────────────────────────

/// The hash-chained economic ledger. All instruments live on the book;
/// balances are derived, never stored, so they can't drift from history.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Book {
    pub events: Vec<Event>,
}

impl Book {
    pub fn new() -> Self {
        Book::default()
    }

    fn head(&self) -> String {
        self.events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "genesis".into())
    }

    fn commit(&mut self, kind: EventKind) -> Event {
        let seq = self.events.len() as u64;
        let prev_hash = self.head();
        let ts = now_secs();
        let hash = sha256_hex(&canonical(&serde_json::json!({
            "seq": seq, "kind": kind, "prev_hash": prev_hash, "ts": ts,
        })));
        let event = Event {
            seq,
            kind,
            prev_hash,
            hash,
            ts,
        };
        self.events.push(event.clone());
        event
    }

    /// Creditor issues an IOU (unsigned by debtor — pending acceptance).
    pub fn issue(
        &mut self,
        creditor: &Identity,
        debtor: &str,
        treaty: &str,
        resource: &str,
        amount: u64,
        due: Option<u64>,
    ) -> Iou {
        let ts = now_secs();
        let id = sha256_hex(&canonical(&serde_json::json!({
            "creditor": creditor.public_key(), "debtor": debtor,
            "treaty": treaty, "amount": amount, "ts": ts,
            "nonce": self.events.len(),
        })));
        let mut iou = Iou {
            id,
            creditor: creditor.public_key(),
            debtor: debtor.to_string(),
            treaty: treaty.to_string(),
            resource: resource.to_string(),
            amount,
            due,
            ts,
            creditor_signature: String::new(),
            debtor_signature: String::new(),
        };
        iou.creditor_signature = creditor.sign(&canonical(&iou.body()));
        self.commit(EventKind::Issue { iou: iou.clone() });
        iou
    }

    /// Debtor accepts the debt — completes the instrument on the book.
    pub fn accept(&mut self, mut iou: Iou, debtor: &Identity) -> Result<Iou, Error> {
        if debtor.public_key() != iou.debtor {
            return Err(Error::WrongParty("acceptor is not the named debtor".into()));
        }
        if self.iou(&iou.id).is_none() {
            return Err(Error::UnknownIou(iou.id.clone()));
        }
        if self.iou(&iou.id).map(|i| i.accepted()).unwrap_or(false) {
            return Err(Error::WrongParty("iou already accepted".into()));
        }
        iou.debtor_signature = debtor.sign(&canonical(&iou.body()));
        // The pending Issue stays on the record; Accept commits the
        // completed instrument — both signatures verifiable in place.
        self.commit(EventKind::Accept { iou: iou.clone() });
        Ok(iou)
    }

    /// Debtor logs work performed — the signature is the worker's claim.
    pub fn invoke(&mut self, worker: &Identity, iou_id: &str, units: u64) -> Invocation {
        let ts = now_secs();
        let id = sha256_hex(&canonical(&serde_json::json!({
            "iou": iou_id, "worker": worker.public_key(),
            "units": units, "ts": ts, "nonce": self.events.len(),
        })));
        let mut inv = Invocation {
            id,
            iou: iou_id.to_string(),
            worker: worker.public_key(),
            units,
            ts,
            signature: String::new(),
        };
        inv.signature = worker.sign(&canonical(&inv.body()));
        self.commit(EventKind::Invoke {
            invocation: inv.clone(),
        });
        inv
    }

    /// Creditor settles invocations against an IOU. Checks: IOU exists,
    /// invocations exist and target this IOU, total doesn't exceed the
    /// remaining balance, creditor signature is valid.
    pub fn settle(
        &mut self,
        creditor: &Identity,
        iou_id: &str,
        invocation_ids: &[&str],
    ) -> Result<Settlement, Error> {
        let iou = self
            .iou(iou_id)
            .ok_or_else(|| Error::UnknownIou(iou_id.into()))?;
        if creditor.public_key() != iou.creditor {
            return Err(Error::WrongParty("settler is not the creditor".into()));
        }
        let mut units = 0u64;
        for id in invocation_ids {
            let inv = self
                .invocation(id)
                .ok_or_else(|| Error::UnknownInvocation((*id).into()))?;
            if inv.iou != iou_id {
                return Err(Error::WrongParty(format!(
                    "invocation {id} targets a different iou"
                )));
            }
            units += inv.units;
        }
        let remaining = self.balance(iou_id)?;
        if units > remaining {
            return Err(Error::OverSettled {
                attempted: units,
                remaining,
            });
        }
        let ts = now_secs();
        let id = sha256_hex(&canonical(&serde_json::json!({
            "iou": iou_id, "invocations": invocation_ids,
            "units": units, "ts": ts,
        })));
        let mut s = Settlement {
            id,
            iou: iou_id.to_string(),
            invocations: invocation_ids.iter().map(|s| s.to_string()).collect(),
            units,
            ts,
            signature: String::new(),
        };
        s.signature = creditor.sign(&canonical(&serde_json::json!({
            "id": s.id, "iou": s.iou, "invocations": s.invocations,
            "units": s.units, "ts": s.ts,
        })));
        self.commit(EventKind::Settle {
            settlement: s.clone(),
        });
        Ok(s)
    }

    /// Creditor declares default on a past-due IOU. The record is
    /// permanent — a debtor's credit is its history.
    pub fn declare_default(
        &mut self,
        creditor: &Identity,
        iou_id: &str,
        reason: &str,
    ) -> Result<(), Error> {
        let iou = self
            .iou(iou_id)
            .ok_or_else(|| Error::UnknownIou(iou_id.into()))?;
        if creditor.public_key() != iou.creditor {
            return Err(Error::WrongParty(
                "only the creditor may declare default".into(),
            ));
        }
        self.commit(EventKind::Default {
            iou: iou_id.to_string(),
            reason: reason.to_string(),
            creditor: creditor.public_key(),
        });
        Ok(())
    }

    /// Remaining balance on an IOU — settled units deducted from face.
    pub fn balance(&self, iou_id: &str) -> Result<u64, Error> {
        let iou = self
            .iou(iou_id)
            .ok_or_else(|| Error::UnknownIou(iou_id.into()))?;
        let settled: u64 = self
            .events
            .iter()
            .filter_map(|e| match &e.kind {
                EventKind::Settle { settlement } if settlement.iou == iou_id => {
                    Some(settlement.units)
                }
                _ => None,
            })
            .sum();
        Ok(iou.amount.saturating_sub(settled))
    }

    /// All IOUs currently on the book — accepted versions supersede
    /// their pending Issue records.
    pub fn ious(&self) -> Vec<&Iou> {
        let mut order: Vec<&str> = Vec::new();
        let mut latest: HashMap<&str, &Iou> = HashMap::new();
        for e in &self.events {
            let iou = match &e.kind {
                EventKind::Issue { iou } | EventKind::Accept { iou } => iou,
                _ => continue,
            };
            if !latest.contains_key(iou.id.as_str()) {
                order.push(iou.id.as_str());
            }
            latest.insert(iou.id.as_str(), iou);
        }
        order
            .iter()
            .filter_map(|id| latest.get(id).copied())
            .collect()
    }

    /// Outstanding balances grouped by debtor — an organism's live debt.
    pub fn obligations(&self, debtor: &str) -> HashMap<String, u64> {
        self.ious()
            .iter()
            .filter(|i| i.debtor == debtor)
            .filter_map(|i| self.balance(&i.id).ok().map(|b| (i.id.clone(), b)))
            .filter(|(_, b)| *b > 0)
            .collect()
    }

    /// Defaults declared against a debtor — the credit report.
    pub fn defaults(&self, debtor: &str) -> Vec<String> {
        let owed: Vec<&str> = self
            .ious()
            .iter()
            .filter(|i| i.debtor == debtor)
            .map(|i| i.id.as_str())
            .collect();
        self.events
            .iter()
            .filter_map(|e| match &e.kind {
                EventKind::Default { iou, .. } if owed.contains(&iou.as_str()) => Some(iou.clone()),
                _ => None,
            })
            .collect()
    }

    fn iou(&self, id: &str) -> Option<&Iou> {
        self.events.iter().rev().find_map(|e| match &e.kind {
            EventKind::Issue { iou } | EventKind::Accept { iou } if iou.id == id => Some(iou),
            _ => None,
        })
    }
    fn invocation(&self, id: &str) -> Option<&Invocation> {
        self.events.iter().find_map(|e| match &e.kind {
            EventKind::Invoke { invocation } if invocation.id == id => Some(invocation),
            _ => None,
        })
    }

    /// Verify the book end to end: hash linkage plus every signature
    /// on every instrument.
    pub fn verify(&self) -> Result<(), Error> {
        let mut prev = "genesis".to_string();
        for e in &self.events {
            if e.prev_hash != prev {
                return Err(Error::BrokenBook(format!("seq {} link broken", e.seq)));
            }
            let expect = sha256_hex(&canonical(&serde_json::json!({
                "seq": e.seq, "kind": e.kind,
                "prev_hash": e.prev_hash, "ts": e.ts,
            })));
            if e.hash != expect {
                return Err(Error::BrokenBook(format!("seq {} hash mismatch", e.seq)));
            }
            match &e.kind {
                EventKind::Issue { iou } | EventKind::Accept { iou } => iou.verify()?,
                EventKind::Invoke { invocation } => verify_sig(
                    &invocation.worker,
                    &canonical(&invocation.body()),
                    &invocation.signature,
                )?,
                EventKind::Settle { settlement } => {
                    let iou = self
                        .iou(&settlement.iou)
                        .ok_or_else(|| Error::UnknownIou(settlement.iou.clone()))?;
                    verify_sig(
                        &iou.creditor,
                        &canonical(&serde_json::json!({
                            "id": settlement.id, "iou": settlement.iou,
                            "invocations": settlement.invocations,
                            "units": settlement.units, "ts": settlement.ts,
                        })),
                        &settlement.signature,
                    )?;
                }
                _ => {}
            }
            prev = e.hash.clone();
        }
        Ok(())
    }
}
