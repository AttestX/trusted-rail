//! Durable authorization state for the agents one enforcer runs.
//!
//! The engine in `trusted-rail` decides and keeps nothing. This crate keeps what
//! a decision depends on and leaves behind: the active policy, the state and its
//! root, and the chain of decision records waiting to be proven.
//!
//! A ledger is not a global service. Whoever enforces for an agent opens one
//! beside the enforcer and holds that agent's entries only. The caller of
//! [`Ledger::decide`] supplies what it observed; it can never supply the state
//! or the policy, so it cannot present a budget other than the stored one.
//!
//! The ledger is trusted storage: a host that can rewrite the file can roll the
//! state back. Proven batches carry their first and last roots, so a verifier
//! that accepts a batch only where the last one ended detects that.
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use trusted_contracts::{ExecutionIdentity, Validity};
use trusted_rail::{
    action::{Action, Subject},
    rego::{
        batch_record, canonical_bytes, commitment, encode_batch_public_values,
        encode_batch_witness, engine_profile, policy_digest, state_root, RegorusEngine, MAX_BATCH,
    },
    BatchRecord, DecisionRecord, Error, EvaluationRequest, PolicyBundle, Result,
};

/// The root of an agent whose policy keeps no state.
pub const NO_STATE_ROOT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Checks a proof receipt. The ledger has no prover and no proof system of its
/// own; the embedding service supplies the real verifier.
pub trait ProofVerifier: Send + Sync {
    /// Succeeds only when `receipt` proves that the approved guest program
    /// committed exactly `public_values`.
    fn verify(&self, public_values: &[u8], receipt: &[u8]) -> Result<()>;
}

/// The authenticated circumstances of one action: who acts, as which
/// execution, and when. The enforcer fills this in from what it observed.
pub struct Attempt {
    pub execution: ExecutionIdentity,
    pub principal: String,
    /// Unique per execution. A repeated id is refused, not decided twice.
    pub action_id: String,
    pub context: Value,
    pub evaluated_at_unix: u64,
    pub validity: Validity,
}

/// Where an agent's chain stands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Head {
    pub state_root: String,
    pub state: Option<Value>,
    /// Decisions recorded, and how many of them a proof covers so far.
    pub decisions: u64,
    pub proven: u64,
    pub active: bool,
}

/// The next run of unproven decisions, ready for a prover.
pub struct Batch {
    pub policy: PolicyBundle,
    pub requests: Vec<EvaluationRequest>,
    pub records: Vec<DecisionRecord>,
    /// What the proof must commit to.
    pub summary: BatchRecord,
    /// The guest's input.
    pub witness: Vec<u8>,
}

pub struct Ledger {
    connection: Mutex<Connection>,
    verifier: Arc<dyn ProofVerifier>,
}

fn db<T>(value: rusqlite::Result<T>) -> Result<T> {
    value.map_err(|_| Error::Unavailable)
}
fn text(value: &impl Serialize) -> Result<String> {
    String::from_utf8(canonical_bytes(value)?).map_err(|_| Error::InvalidInput)
}
fn stored<T: DeserializeOwned>(text: &str) -> Result<T> {
    serde_json::from_str(text).map_err(|_| Error::Unavailable)
}
fn number(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::InvalidInput)
}
fn execution_key(execution: &ExecutionIdentity) -> Result<String> {
    commitment("trusted-rail.ledger.execution.v1", execution)
}
fn approved(policy: &PolicyBundle) -> Result<()> {
    if policy_digest(policy)? != policy.policy.sha256 || policy.engine != engine_profile() {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

struct Agent {
    policy: String,
    state: Option<String>,
    root: String,
    decisions: i64,
    proven: i64,
    last_at: i64,
    active: bool,
}

fn agent(connection: &Connection, key: &str) -> Result<Option<Agent>> {
    db(connection
        .query_row(
            "SELECT policy,state,root,decisions,proven,last_at,active FROM agents WHERE execution=?1",
            params![key],
            |row| {
                Ok(Agent {
                    policy: row.get(0)?,
                    state: row.get(1)?,
                    root: row.get(2)?,
                    decisions: row.get(3)?,
                    proven: row.get(4)?,
                    last_at: row.get(5)?,
                    active: row.get(6)?,
                })
            },
        )
        .optional())
}

fn bundle(connection: &Connection, sha: &str) -> Result<PolicyBundle> {
    let text: String = db(connection.query_row(
        "SELECT bundle FROM policies WHERE sha=?1",
        params![sha],
        |row| row.get(0),
    ))?;
    stored(&text)
}

impl Ledger {
    /// Opens or creates the ledger file. Its directory must be private to the
    /// owner: the file holds every agent's policy and state.
    pub fn open(path: &Path, verifier: Arc<dyn ProofVerifier>) -> Result<Self> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let parent = path.parent().ok_or(Error::InvalidInput)?;
        let meta = std::fs::symlink_metadata(parent).map_err(|_| Error::Unavailable)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::InvalidInput);
        }
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| Error::Unavailable)?;
            let meta = file.metadata().map_err(|_| Error::Unavailable)?;
            if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
                return Err(Error::InvalidInput);
            }
            // Closed here, before SQLite opens the file. Closing any handle on a
            // file drops every lock this process holds on it, SQLite's included;
            // another process would then take the database for unused and
            // remove the write-ahead log under a live connection.
        }
        let connection = db(Connection::open(path))?;
        db(connection.busy_timeout(std::time::Duration::from_secs(5)))?;
        db(connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS policies(sha TEXT PRIMARY KEY, bundle TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS revoked(execution TEXT PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS agents(
               execution TEXT PRIMARY KEY, policy TEXT NOT NULL REFERENCES policies(sha),
               state TEXT, root TEXT NOT NULL, decisions INTEGER NOT NULL DEFAULT 0,
               proven INTEGER NOT NULL DEFAULT 0, last_at INTEGER NOT NULL DEFAULT 0,
               active INTEGER NOT NULL DEFAULT 1);
             CREATE TABLE IF NOT EXISTS records(
               execution TEXT NOT NULL REFERENCES agents(execution), seq INTEGER NOT NULL,
               action TEXT NOT NULL, policy TEXT NOT NULL REFERENCES policies(sha),
               request TEXT NOT NULL, record TEXT NOT NULL,
               PRIMARY KEY(execution,seq), UNIQUE(execution,action));
             CREATE TABLE IF NOT EXISTS proofs(
               execution TEXT NOT NULL REFERENCES agents(execution), first INTEGER NOT NULL,
               summary TEXT NOT NULL, receipt BLOB NOT NULL, PRIMARY KEY(execution,first));",
        ))?;
        Ok(Self {
            connection: Mutex::new(connection),
            verifier,
        })
    }

    fn store_policy(connection: &Connection, policy: &PolicyBundle) -> Result<()> {
        approved(policy)?;
        db(connection.execute(
            "INSERT OR IGNORE INTO policies VALUES(?1,?2)",
            params![policy.policy.sha256, text(policy)?],
        ))?;
        Ok(())
    }

    /// Starts an agent's chain under an approved policy. `state` is where the
    /// chain begins: `None` for a policy that keeps no state, a fresh state for
    /// a new agent, or the state an agent carried over from where it ran before.
    /// Repeating the same activation is harmless; a revoked execution never
    /// comes back, so a restart needs a new lease or generation.
    pub fn activate(
        &self,
        execution: &ExecutionIdentity,
        policy: &PolicyBundle,
        state: Option<&Value>,
    ) -> Result<()> {
        let root = match state {
            Some(state) => state_root(state)?,
            None => NO_STATE_ROOT.into(),
        };
        let state = state.map(text).transpose()?;
        let key = execution_key(execution)?;
        let mut connection = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if db(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked WHERE execution=?1)",
            params![key],
            |row| row.get::<_, bool>(0),
        ))? {
            return Err(Error::Rejected);
        }
        Self::store_policy(&tx, policy)?;
        match agent(&tx, &key)? {
            None => {
                db(tx.execute(
                    "INSERT INTO agents(execution,policy,state,root) VALUES(?1,?2,?3,?4)",
                    params![key, policy.policy.sha256, state, root],
                ))?;
            }
            Some(old)
                if old.decisions == 0 && old.policy == policy.policy.sha256 && old.root == root => {
            }
            Some(_) => return Err(Error::Conflict),
        }
        db(tx.commit())
    }

    /// Replaces a running agent's policy and keeps its state, so changing a
    /// limit does not reset what was spent. Later decisions use the new policy;
    /// a proof batch never spans the change.
    pub fn set_policy(&self, execution: &ExecutionIdentity, policy: &PolicyBundle) -> Result<()> {
        let key = execution_key(execution)?;
        let mut connection = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
        Self::store_policy(&tx, policy)?;
        if db(tx.execute(
            "UPDATE agents SET policy=?1 WHERE execution=?2 AND active=1",
            params![policy.policy.sha256, key],
        ))? != 1
        {
            return Err(Error::Rejected);
        }
        db(tx.commit())
    }

    /// Ends an agent's chain for good. Recorded even when the activation has not
    /// arrived, so reordered lifecycle messages cannot revive a retired agent.
    /// Its recorded decisions can still be proven.
    pub fn revoke(&self, execution: &ExecutionIdentity) -> Result<()> {
        let key = execution_key(execution)?;
        let mut connection = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
        db(tx.execute("INSERT OR IGNORE INTO revoked VALUES(?1)", params![key]))?;
        db(tx.execute(
            "UPDATE agents SET active=0 WHERE execution=?1",
            params![key],
        ))?;
        db(tx.commit())
    }

    /// Decides one action against the agent's current policy and state and, in
    /// the same transaction, records the decision and moves the state. Deny and
    /// approval-required decisions are recorded too and leave the state as it
    /// was. An error records nothing; the caller must treat it as a refusal.
    pub fn decide(&self, action: Action, attempt: Attempt) -> Result<DecisionRecord> {
        let key = execution_key(&attempt.execution)?;
        let at = number(attempt.evaluated_at_unix)?;
        let mut connection = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let agent = agent(&tx, &key)?
            .filter(|agent| agent.active)
            .ok_or(Error::Rejected)?;
        // A proof batch requires time to move forward along the chain.
        if at < agent.last_at
            || db(tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM records WHERE execution=?1 AND action=?2)",
                params![key, attempt.action_id],
                |row| row.get::<_, bool>(0),
            ))?
        {
            return Err(Error::Conflict);
        }
        let policy = bundle(&tx, &agent.policy)?;
        let request = action.request(Subject {
            execution: attempt.execution,
            principal: attempt.principal,
            action_id: attempt.action_id,
            context: attempt.context,
            previous_state_root: agent.root,
            state: agent.state.as_deref().map(stored).transpose()?,
            evaluated_at_unix: attempt.evaluated_at_unix,
            validity: attempt.validity,
        });
        let moved = RegorusEngine.transition(&policy, &request)?;
        db(tx.execute(
            "INSERT INTO records VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                key,
                agent.decisions,
                request.action_id,
                agent.policy,
                text(&request)?,
                text(&moved.record)?
            ],
        ))?;
        let state = match &moved.next_state {
            Some(next) => Some(text(next)?),
            None => agent.state,
        };
        db(tx.execute(
            "UPDATE agents SET state=?1,root=?2,decisions=decisions+1,last_at=?3 WHERE execution=?4",
            params![state, moved.record.next_state_root, at, key],
        ))?;
        db(tx.commit())?;
        Ok(moved.record)
    }

    pub fn head(&self, execution: &ExecutionIdentity) -> Result<Head> {
        let connection = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let agent = agent(&connection, &execution_key(execution)?)?.ok_or(Error::Rejected)?;
        Ok(Head {
            state_root: agent.root,
            state: agent.state.as_deref().map(stored).transpose()?,
            decisions: agent.decisions as u64,
            proven: agent.proven as u64,
            active: agent.active,
        })
    }

    /// The unproven decisions that follow the last proven one, at most `limit`
    /// of them, all under one policy and small enough for one witness.
    pub fn next_batch(&self, execution: &ExecutionIdentity, limit: usize) -> Result<Option<Batch>> {
        let connection = self.connection.lock().map_err(|_| Error::Unavailable)?;
        Self::unproven(&connection, &execution_key(execution)?, limit)
    }

    fn unproven(connection: &Connection, key: &str, limit: usize) -> Result<Option<Batch>> {
        let agent = agent(connection, key)?.ok_or(Error::Rejected)?;
        let limit = number(limit.clamp(1, MAX_BATCH) as u64)?;
        let mut statement = db(connection.prepare(
            "SELECT policy,request,record FROM records WHERE execution=?1 AND seq>=?2
             ORDER BY seq LIMIT ?3",
        ))?;
        let rows: Vec<(String, String, String)> = db(db(statement
            .query_map(params![key, agent.proven, limit], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            }))?
        .collect())?;
        let Some(sha) = rows.first().map(|row| row.0.clone()) else {
            return Ok(None);
        };
        let policy = bundle(connection, &sha)?;
        let (mut requests, mut records) = (Vec::new(), Vec::new());
        for (_, request, record) in rows.iter().take_while(|row| row.0 == sha) {
            requests.push(stored::<EvaluationRequest>(request)?);
            records.push(stored::<DecisionRecord>(record)?);
        }
        // Shorten the run until its witness fits; one decision always must.
        let witness = loop {
            match encode_batch_witness(&policy, &requests) {
                Ok(witness) => break witness,
                Err(_) if requests.len() > 1 => {
                    requests.pop();
                    records.pop();
                }
                Err(error) => return Err(error),
            }
        };
        Ok(Some(Batch {
            summary: batch_record(&records)?,
            policy,
            requests,
            records,
            witness,
        }))
    }

    /// Accepts a proof of the next unproven run. `summary` must be exactly what
    /// the stored records give, starting where the last proof ended, so a proof
    /// of some other run, or of this run out of order, is refused.
    pub fn record_proof(
        &self,
        execution: &ExecutionIdentity,
        summary: &BatchRecord,
        receipt: &[u8],
    ) -> Result<()> {
        let key = execution_key(execution)?;
        let covered = |connection: &Connection| -> Result<i64> {
            let agent = agent(connection, &key)?.ok_or(Error::Rejected)?;
            let batch = Self::unproven(connection, &key, summary.count as usize)?;
            match batch {
                Some(batch) if batch.summary == *summary => Ok(agent.proven),
                _ => Err(Error::Conflict),
            }
        };
        // The verifier may be slow; decisions must not wait behind it.
        let first = covered(&*self.connection.lock().map_err(|_| Error::Unavailable)?)?;
        if receipt.is_empty() {
            return Err(Error::Rejected);
        }
        self.verifier
            .verify(&encode_batch_public_values(summary)?, receipt)
            .map_err(|_| Error::Rejected)?;
        let mut connection = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if covered(&tx)? != first {
            return Err(Error::Conflict);
        }
        db(tx.execute(
            "INSERT INTO proofs VALUES(?1,?2,?3,?4)",
            params![key, first, text(summary)?, receipt],
        ))?;
        db(tx.execute(
            "UPDATE agents SET proven=proven+?1 WHERE execution=?2",
            params![summary.count, key],
        ))?;
        db(tx.commit())
    }

    /// Every accepted proof in chain order, with its receipt, for a verifier
    /// elsewhere to check that each starts where the one before it ended.
    pub fn proofs(&self, execution: &ExecutionIdentity) -> Result<Vec<(BatchRecord, Vec<u8>)>> {
        let connection = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let mut statement = db(connection
            .prepare("SELECT summary,receipt FROM proofs WHERE execution=?1 ORDER BY first"))?;
        let rows: Vec<(String, Vec<u8>)> = db(db(statement
            .query_map(params![execution_key(execution)?], |row| {
                Ok((row.get(0)?, row.get(1)?))
            }))?
        .collect())?;
        rows.into_iter()
            .map(|(summary, receipt)| Ok((stored(&summary)?, receipt)))
            .collect()
    }
}
