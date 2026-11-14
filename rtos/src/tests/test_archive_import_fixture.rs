// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::block_proof::BlockProofStuff;
use rtos_block::*;
use storage::archives::{
    package::Package,
    package_entry::PackageEntry,
    package_entry_id::{GetFileName, PackageEntryId},
};

/// Public synthetic, signed MC history with WC inclusion and matching state updates.
/// This tests authenticated storage import, not transaction execution validity.
pub struct Fixture {
    data: serde_json::Value,
}
impl Fixture {
    pub fn chains(&self) -> Vec<bool> {
        if self.data["masterchain_only"].as_bool() == Some(true) {
            vec![false]
        } else {
            vec![false, true]
        }
    }
    #[cfg(feature = "isolated-consensus-signing")]
    pub fn active_validator() -> Result<Self> {
        let generated = std::process::Command::new(std::env::var("RTOS_ACTIVE_FIXTURE_GENERATOR")?)
            .arg("--active-validator")
            .output()?;
        assert!(generated.status.success(), "active history generator failed");
        let mut data: serde_json::Value = serde_json::from_slice(&generated.stdout)?;
        for row in data["cases"].as_array_mut().unwrap() {
            let signed = std::process::Command::new(std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER")?)
                .args([
                    "1",
                    row["preimage"].as_str().unwrap(),
                    &hex::encode(b"TOS-CONSENSUS-SIMPLEX-v1"),
                ])
                .output()?;
            assert!(signed.status.success(), "public fixture signing failed");
            let text = std::str::from_utf8(&signed.stdout)?;
            let signature = text.lines().nth(1).unwrap();
            assert_eq!(hex::decode(signature)?.len(), 2420);
            row["signature"] = signature.into();
        }
        Ok(Self { data })
    }
    #[cfg(feature = "isolated-consensus-signing")]
    pub fn active_network() -> Result<Self> {
        let stores = (0..4)
            .map(|i| rtos_pq_consensus::ConsensusKeyStore::from_seed(&[0xa0 + i; 32], u32::MAX))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let keys = tempfile::NamedTempFile::new()?;
        std::fs::write(
            keys.path(),
            serde_json::to_vec(
                &stores
                    .iter()
                    .map(|k| hex::encode(&k.consensus_key().public_key))
                    .collect::<Vec<_>>(),
            )?,
        )?;
        let generated = std::process::Command::new(std::env::var("RTOS_ACTIVE_FIXTURE_GENERATOR")?)
            .arg("--active-network-keys")
            .arg(keys.path())
            .output()?;
        assert!(generated.status.success(), "four-validator history generator failed");
        let mut data: serde_json::Value = serde_json::from_slice(&generated.stdout)?;
        for row in data["cases"].as_array_mut().unwrap() {
            let preimage = hex::decode(row["preimage"].as_str().unwrap())?;
            let signatures = stores
                .iter()
                .enumerate()
                .map(|(i, store)| {
                    Ok(serde_json::json!({
                        "validator_id":hex::encode([i as u8 + 1; 32]),
                        "signature":hex::encode(store.sign_consensus(&preimage)?.bytes),
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            row["signatures"] = signatures.into();
        }
        Ok(Self { data })
    }
    pub fn node_finality() -> Self {
        Self {
            data: serde_json::from_str(include_str!("static/node-finality-history.json")).unwrap(),
        }
    }
    pub fn node_recovery() -> Self {
        Self {
            data: serde_json::from_str(include_str!("static/node-recovery-history.json")).unwrap(),
        }
    }
    pub fn new() -> Self {
        Self { data: serde_json::from_str(include_str!("static/archive-mc-wc.json")).unwrap() }
    }
    fn bytes(&self, seq: u32, wc: bool, state: bool) -> Vec<u8> {
        let field = if seq == 0 {
            if wc {
                "wc_zerostate"
            } else {
                "zerostate"
            }
        } else {
            match (wc, state) {
                (false, false) => "block_boc",
                (false, true) => "state_boc",
                (true, false) => "wc_block_boc",
                (true, true) => "wc_state_boc",
            }
        };
        hex::decode(if seq == 0 {
            self.data[field].as_str().unwrap()
        } else {
            self.data["cases"][(seq - 1) as usize][field].as_str().unwrap()
        })
        .unwrap()
    }
    pub fn id(&self, seq: u32, wc: bool) -> BlockIdExt {
        let bytes = self.bytes(seq, wc, false);
        let root = read_single_root_boc(&bytes).unwrap();
        BlockIdExt::with_params(
            if wc {
                ShardIdent::with_tagged_prefix(0, SHARD_FULL).unwrap()
            } else {
                ShardIdent::masterchain()
            },
            seq,
            root.repr_hash().clone(),
            UInt256::calc_file_hash(&bytes),
        )
    }
    fn proof(&self, seq: u32, wc: bool) -> Result<BlockProofStuff> {
        let root = read_single_root_boc(&self.bytes(seq, wc, false))?;
        let row = &self.data["cases"][(seq - 1) as usize];
        let signatures = if wc {
            None
        } else {
            Some(BlockSignaturesVariant::SimplexPq(BlockSignaturesSimplexPq {
                validator_info: ValidatorBaseInfo::with_params(
                    row["subset_hash"].as_u64().unwrap() as u32,
                    row["catchain_seqno"].as_u64().unwrap_or(7) as u32,
                ),
                session_id: UInt256::from_slice(&hex::decode(row["session"].as_str().unwrap())?),
                slot: row["slot"].as_u64().unwrap() as u32,
                candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&hex::decode(
                    row["candidate"].as_str().unwrap(),
                )?)?,
                sig_count: if self.data["active_network"] == true { 4 } else { 1 },
                sig_weight: if self.data["active_network"] == true { 4 } else { 2 },
                signatures: if self.data["active_network"] == true {
                    row["signatures"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| {
                            Ok(PqBlockSignaturePair {
                                validator_id: UInt256::from_slice(&hex::decode(
                                    s["validator_id"].as_str().unwrap(),
                                )?),
                                algorithm_id: 1,
                                signature: hex::decode(s["signature"].as_str().unwrap())?,
                            })
                        })
                        .collect::<Result<Vec<_>>>()?
                } else {
                    vec![PqBlockSignaturePair {
                        validator_id: UInt256::from([2; 32]),
                        algorithm_id: 1,
                        signature: hex::decode(row["signature"].as_str().unwrap())?,
                    }]
                },
            }))
        };
        BlockProofStuff::new(
            BlockProof::with_params(
                self.id(seq, wc),
                MerkleProof::create(&root, |_| true)?.serialize()?,
                signatures,
            ),
            wc,
        )
    }
    pub async fn prepare(&self, dir: &Path, archives: &Path) -> Result<()> {
        let package_context_dir = tempfile::tempdir()?;
        let package_context_db = storage::db::rocksdb::RocksDb::new(
            package_context_dir.path(),
            "provider",
            None,
            storage::db::rocksdb::AccessType::ReadWrite,
        )?;
        let package_view = package_context_db
            .bind_archive_domain(storage::archives::context::ArchiveDomain::new())?
            .view()?;
        let package_operation = package_view.enter()?;

        std::fs::create_dir_all(archives)?;
        std::fs::write(dir.join("authenticated-mc-zero.boc"), self.bytes(0, false, false))?;
        std::fs::write(dir.join("authenticated-wc-zero.boc"), self.bytes(0, true, false))?;
        let pin = self.id(0, false);
        let mut global: serde_json::Value =
            serde_json::from_str(include_str!("config/mainnet.json"))?;
        global["validator"] = serde_json::json!({"zero_state":{"workchain":-1,"shard":i64::MIN,"seqno":0,"root_hash":pin.root_hash.as_base64(false),"file_hash":pin.file_hash.as_base64(false)}});
        std::fs::write(dir.join("authenticated-global.json"), serde_json::to_vec(&global)?)?;
        for start in [1, 3] {
            for wc in self.chains() {
                let path = archives.join(if wc {
                    format!("archive.{start:05}.0:8000000000000000.pack")
                } else {
                    format!("archive.{start:05}.pack")
                });
                let package =
                    Package::open(package_view.clone(), &package_operation, path, false, true)
                        .await?;
                for seq in start..=start + 1 {
                    let id = self.id(seq, wc);
                    let proof = self.proof(seq, wc)?;
                    package
                        .append_entry(
                            PackageEntry::with_data(
                                PackageEntryId::Block(id.clone()).filename(),
                                self.bytes(seq, wc, false),
                            ),
                            |_, _| Ok(()),
                        )
                        .await?;
                    let proofid =
                        if wc { PackageEntryId::ProofLink(id) } else { PackageEntryId::Proof(id) };
                    package
                        .append_entry(
                            PackageEntry::with_data(proofid.filename(), proof.data().to_vec()),
                            |_, _| Ok(()),
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }
    pub fn config(&self, dir: &Path, archives_path: PathBuf) -> ImportConfig {
        ImportConfig {
            archives_path,
            epochs_path: dir.join("epochs"),
            epoch_size: 20_000,
            node_db_path: dir.join("node_db"),
            mc_zerostate_path: dir.join("authenticated-mc-zero.boc"),
            wc_zerostate_paths: vec![dir.join("authenticated-wc-zero.boc")],
            global_config_path: dir.join("authenticated-global.json"),
            skip_validation: false,
            move_files: false,
        }
    }
    pub async fn assert_imported(&self, db: &InternalDb, through: u32) -> Result<()> {
        let expected = self.id(through, false);
        for key in
            [LAST_APPLIED_MC_BLOCK, ARCHIVES_GC_BLOCK, PSS_KEEPER_MC_BLOCK, SHARD_CLIENT_MC_BLOCK]
        {
            assert_eq!(db.load_full_node_state(key)?.as_deref(), Some(&expected), "cursor {key}");
        }
        self.assert_history(db, through).await
    }
    pub async fn assert_history(&self, db: &InternalDb, through: u32) -> Result<()> {
        for seq in 0..=through {
            for wc in self.chains() {
                let id = self.id(seq, wc);
                let block = check_imported_block(db, &id).await?;
                let loaded = db.load_shard_state_dynamic(&id)?;
                assert_eq!(
                    loaded.root_cell().repr_hash(),
                    read_single_root_boc(&self.bytes(seq, wc, true))?.repr_hash(),
                    "state {id}"
                );
                if seq > 0 {
                    let indexed = db
                        .lookup_block_by_seqno(
                            &if wc {
                                AccountIdPrefixFull::workchain(0, SHARD_FULL)
                            } else {
                                AccountIdPrefixFull::any_masterchain()
                            },
                            seq,
                        )
                        .await?
                        .unwrap_or_else(|| panic!("missing index for imported block {id}"));
                    assert_eq!(indexed.0, id);
                    let block = block.unwrap();
                    assert_eq!(block.construct_prev_id()?.0, self.id(seq - 1, wc));
                    if wc {
                        let master = block.block()?.read_info()?.read_master_ref()?.unwrap().master;
                        let prevmc = self.id(seq - 1, false);
                        assert_eq!(master.seq_no, prevmc.seq_no);
                        assert_eq!(master.root_hash, prevmc.root_hash);
                        assert_eq!(master.file_hash, prevmc.file_hash);
                        assert_eq!(loaded.state()?.master_ref().unwrap().master, master);
                    } else {
                        let expected_shards = if self.chains().len() == 1 {
                            vec![]
                        } else {
                            vec![self.id(seq, true)]
                        };
                        assert_eq!(block.top_blocks_all()?, expected_shards);
                        assert_eq!(
                            crate::shard_state::ShardHashesStuff::from(
                                loaded.shard_state_extra()?.shards.clone()
                            )
                            .top_blocks_all()?,
                            expected_shards
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
