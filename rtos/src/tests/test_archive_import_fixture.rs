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
                    7,
                ),
                session_id: UInt256::from_slice(&hex::decode(row["session"].as_str().unwrap())?),
                slot: row["slot"].as_u64().unwrap() as u32,
                candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&hex::decode(
                    row["candidate"].as_str().unwrap(),
                )?)?,
                sig_count: 1,
                sig_weight: 2,
                signatures: vec![PqBlockSignaturePair {
                    validator_id: UInt256::from([2; 32]),
                    algorithm_id: 1,
                    signature: hex::decode(row["signature"].as_str().unwrap())?,
                }],
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
        let package_context_db = storage::db::rocksdb::RocksDb::new(package_context_dir.path(), "provider", None, storage::db::rocksdb::AccessType::ReadWrite)?;
        let package_view = package_context_db.bind_archive_domain(storage::archives::context::ArchiveDomain::new())?.view()?;
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
            for wc in [false, true] {
                let path = archives.join(if wc {
                    format!("archive.{start:05}.0:8000000000000000.pack")
                } else {
                    format!("archive.{start:05}.pack")
                });
                let package = Package::open(package_view.clone(), &package_operation, path, false, true).await?;
                for seq in start..=start + 1 {
                    let id = self.id(seq, wc);
                    let proof = self.proof(seq, wc)?;
                    package
                        .append_entry(
                            &PackageEntry::with_data(
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
                            &PackageEntry::with_data(proofid.filename(), proof.data().to_vec()),
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
        for seq in 0..=through {
            for wc in [false, true] {
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
                        .expect("indexed imported block");
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
                        assert_eq!(block.top_blocks_all()?, vec![self.id(seq, true)]);
                        assert_eq!(
                            crate::shard_state::ShardHashesStuff::from(
                                loaded.shard_state_extra()?.shards.clone()
                            )
                            .top_blocks_all()?,
                            vec![self.id(seq, true)]
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
