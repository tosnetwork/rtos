/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::consensus::{BlockHash, ConsensusFactory, ValidatorBlockCandidate};
use rtos_api::{Deserializer, Serializer};
use rtos_block::{error, fail, Result, UInt256};
use std::{
    fmt::{Display, Formatter},
    io::Cursor,
    sync::Arc,
};
use storage::{
    db::{rocksdb::RocksDb, DbKey},
    db_impl_single,
};

#[derive(PartialEq, Eq, Hash)]
pub struct CandidateDbKey {
    root_hash: BlockHash,
}

impl Display for CandidateDbKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_string())
    }
}

impl DbKey for CandidateDbKey {
    fn key_name(&self) -> &'static str {
        "CandidateDbKey"
    }
    fn as_string(&self) -> String {
        hex::encode(self.root_hash.as_slice())
    }
    fn key(&self) -> &[u8] {
        self.root_hash.as_slice()
    }
}

impl CandidateDbKey {
    fn from_candidate(candidate: &ValidatorBlockCandidate) -> Self {
        Self { root_hash: candidate.id.root_hash.clone() }
    }
}

// This wrapper structure has no separated meanging, and created only for library compatibility issues.
pub struct ValidatorBlockCandidateWrapper {
    candidate: Arc<ValidatorBlockCandidate>,
}

impl ValidatorBlockCandidateWrapper {
    fn serialize(&self) -> Result<Vec<u8>> {
        let candidate = rtos_api::ton::db::candidate::Candidate {
            source: (&self.candidate.public_key).try_into()?,
            id: self.candidate.id.clone(),
            data: self.candidate.data.data().clone(),
            collated_data: self.candidate.collated_data.data().clone(),
        };
        let mut ret = Vec::new();
        Serializer::new(&mut ret).write_bare(&candidate)?;
        Ok(ret)
    }

    fn deserialize(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        match Deserializer::new(&mut cursor).read_bare() {
            Ok(rtos_api::ton::db::candidate::Candidate { source, id, data, collated_data }) => {
                let candidate = ValidatorBlockCandidate {
                    public_key: (&source).try_into()?,
                    id,
                    collated_file_hash: super::consensus::get_hash(&data),
                    data: ConsensusFactory::create_block_payload(data),
                    collated_data: ConsensusFactory::create_block_payload(collated_data),
                };
                Ok(ValidatorBlockCandidateWrapper { candidate: Arc::new(candidate) })
            }
            Err(e) => Err(e),
        }
    }
}

/// Database pool for storing validator block candidates by sessions. A table
/// is opened or created on disk only for an admitted session; admission is
/// granted by the validator manager after the session's durable candidate
/// cleanup claim is erased, and revoked under the same lock when the claim
/// executor destroys the table.
pub struct CandidateDbPool {
    path: String,
    map: lockfree::map::Map<UInt256, Arc<CandidateDb>>,
    admitted: std::sync::Mutex<std::collections::HashSet<UInt256>>,
}

impl CandidateDbPool {
    /// Creates new candidate db pool
    pub fn with_path(path: impl ToString) -> Self {
        Self {
            path: path.to_string(),
            map: lockfree::map::Map::new(),
            admitted: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    fn admitted(&self) -> Result<std::sync::MutexGuard<'_, std::collections::HashSet<UInt256>>> {
        self.admitted.lock().map_err(|_| error!("Candidate admission poisoned"))
    }

    /// Allows `session`'s table to be opened or created.
    pub fn admit(&self, session_id: &UInt256) -> Result<()> {
        self.admitted()?.insert(session_id.clone());
        Ok(())
    }

    /// returns existing db, or opens one for an admitted session
    pub fn get_db(&self, session_id: &UInt256) -> Result<Arc<CandidateDb>> {
        if let Some(db) = self.map.get(session_id) {
            return Ok(db.val().clone());
        }
        let admitted = self.admitted()?;
        if let Some(db) = self.map.get(session_id) {
            return Ok(db.val().clone());
        }
        if !admitted.contains(session_id) {
            fail!("Candidate table for session {:x} is not admitted", session_id);
        }
        let name = format!("catchains/candidates{:x}", session_id);
        let db = Arc::new(CandidateDb::new(&self.path, &name)?);
        self.map.insert(session_id.clone(), db.clone());
        Ok(db)
    }

    /// destroys db for session
    pub fn destroy_db(&self, session_id: &UInt256) -> Result<bool> {
        if let Some(mut removed) = self.map.remove(session_id) {
            if let Some((_, db)) = lockfree::map::Removed::try_as_mut(&mut removed) {
                if let Some(db) = Arc::get_mut(db) {
                    return db.destroy();
                }
            }
            self.map.reinsert(removed);
            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// Session-level cleanup: revokes admission and destroys any open table
    /// under the admission lock, so no open can race it. False while another
    /// holder still shares the open table; admission stays revoked.
    pub fn revoke_and_destroy(&self, session_id: &UInt256) -> Result<bool> {
        let mut admitted = self.admitted()?;
        admitted.remove(session_id);
        self.destroy_db(session_id)
    }
}

db_impl_single!(CandidateDb);

impl CandidateDb {
    pub fn save(&self, candidate: Arc<ValidatorBlockCandidate>) -> Result<()> {
        let key = CandidateDbKey::from_candidate(&candidate);
        self.put(&key, &ValidatorBlockCandidateWrapper { candidate }.serialize()?)
    }

    pub fn load(&self, root_hash: &BlockHash) -> Result<Arc<ValidatorBlockCandidate>> {
        let key = CandidateDbKey { root_hash: root_hash.clone() };
        match self.try_get(&key) {
            Ok(Some(db_slice)) => {
                let value = ValidatorBlockCandidateWrapper::deserialize(db_slice.as_ref())?;
                Ok(value.candidate)
            }
            Ok(None) => Err(error!("Cannot find candidate for {}", key)),
            Err(e) => Err(error!("Operational problem encountered: {}", e)),
        }
    }
}
