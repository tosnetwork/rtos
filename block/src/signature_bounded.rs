// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use crate::config_read_budget::{self as signature_budget, ConfigReadBudget};

impl BlockSignaturesPure {
    pub fn signatures_count_bounded(&self, budget: &dyn ConfigReadBudget) -> Result<usize> {
        let mut count = 0usize;
        self.signatures().iterate_slices_bounded(budget, |_, _| {
            count += 1;
            Ok(true)
        })?;
        Ok(count)
    }
    pub fn check_signatures_bounded(
        &self,
        validators: &[ValidatorDescr],
        data: &[u8],
        budget: &dyn ConfigReadBudget,
    ) -> Result<u64> {
        crate::validators::validate_validator_list_bounded(validators, budget)?;
        let mut members = signature_budget::vector(budget, validators.len())?;
        for v in validators {
            // Ordinary verification rejects PQ members via public_key as well.
            v.public_key()?;
            members.push((v.validator_id_bounded(budget)?, v, false));
        }
        let mut weight = 0;
        self.signatures().iterate_slices_bounded(budget, |_, mut value| {
            let signature = CryptoSignaturePair::construct_from(&mut value)?;
            let mut found = None;
            for entry in &mut members {
                budget.step()?;
                if entry.0 == signature.node_id_short {
                    found = Some(entry);
                    break;
                }
            }
            let (_, validator, used) =
                found.ok_or_else(|| crate::error!("signature from an unknown validator"))?;
            if *used {
                fail!(BlockError::DuplicatedSignature);
            }
            *used = true;
            // SigPubKey::verify_signature constructs these two Arc allocations.
            budget.workspace(
                std::mem::size_of::<Ed25519KeyOption<ZeroizingBytes>>()
                    + std::mem::size_of::<crate::KeyId>()
                    + 4 * std::mem::size_of::<usize>(),
            )?;
            if !validator.verify_signature(data, &signature.sign) {
                fail!(BlockError::BadSignature);
            }
            weight = crate::checked_add_validator_weight(weight, validator.weight)?;
            Ok(true)
        })?;
        Ok(weight)
    }
}

impl BlockSignaturesSimplexPq {
    pub fn candidate_bytes_bounded(&self, budget: &dyn ConfigReadBudget) -> Result<Vec<u8>> {
        read_candidate_data_bounded(&self.candidate_data, budget)
    }
    pub fn validate_structure_bounded(&self, budget: &dyn ConfigReadBudget) -> Result<()> {
        if self.sig_count > PQ_SIGNATURE_MAX_SIGNERS {
            return pq_reject(
                PqBlockSignatureReasonCode::SignerCount,
                "signer count exceeds maximum",
            );
        }
        if self.signatures.len() != self.sig_count as usize {
            return pq_reject(
                PqBlockSignatureReasonCode::DictionaryMissingEntry,
                "signature count mismatch",
            );
        }
        for (i, signature) in self.signatures.iter().enumerate() {
            budget.step()?;
            if signature.algorithm_id != MLDSA44_ALGORITHM_ID {
                return pq_reject(
                    PqBlockSignatureReasonCode::UnsupportedAlgorithm,
                    "unsupported algorithm",
                );
            }
            if signature.signature.len() != PQ_SIGNATURE_BYTES {
                return pq_reject(PqBlockSignatureReasonCode::SignatureLength, "signature length");
            }
            for prior in &self.signatures[..i] {
                budget.step()?;
                if prior.validator_id == signature.validator_id {
                    return pq_reject(
                        PqBlockSignatureReasonCode::DuplicateValidatorId,
                        "duplicate validator_id",
                    );
                }
            }
        }
        self.candidate_bytes_bounded(budget)?;
        // The canonical serializer creates at most 400 leaves, 399 forks,
        // and (20 byte-snake chunks + length root) per 2420-byte signature.
        // < 2^16 cells => two-byte references. Each canonical 16-bit hashmap
        // label is <=23 bits. Leaf <=41 bytes; fork <=9; signature snake
        // <=2506. Root <=64, candidate <=16*(127+2+2), BOC header <=17.
        // Deduplication only reduces this size. Thus all structurally valid
        // in-memory carriers satisfy the SAME 1 MiB serialized-size ceiling.
        const MAX_CANONICAL_SIZE: usize = 400 * (2506 + 41) + 399 * 9 + 64 + 16 * 131 + 17;
        const _: () = assert!(MAX_CANONICAL_SIZE <= PQ_SIGNATURE_BOC_MAX_BYTES);
        Ok(())
    }
    pub fn check_structural_membership_and_weight_bounded(
        &self,
        validators: &[PqBlockValidatorWeight],
        budget: &dyn ConfigReadBudget,
    ) -> Result<u64> {
        self.validate_structure_bounded(budget)?;
        for (i, member) in validators.iter().enumerate() {
            for prior in &validators[..i] {
                budget.step()?;
                if prior.validator_id == member.validator_id {
                    return pq_reject(
                        PqBlockSignatureReasonCode::DuplicateValidatorId,
                        "duplicate governing validator_id",
                    );
                }
            }
        }
        let mut total = 0u64;
        for signature in &self.signatures {
            let mut found = None;
            for member in validators {
                budget.step()?;
                if member.validator_id == signature.validator_id {
                    found = Some(member);
                    break;
                }
            }
            let member = match found {
                Some(value) => value,
                None => {
                    return pq_reject(
                        PqBlockSignatureReasonCode::UnknownValidatorId,
                        "unknown validator_id",
                    )
                }
            };
            if member.algorithm_id != signature.algorithm_id {
                return pq_reject(
                    PqBlockSignatureReasonCode::ValidatorAlgorithmMismatch,
                    "validator algorithm mismatch",
                );
            }
            total = total.checked_add(member.weight).ok_or_else(|| PqBlockSignatureError {
                code: PqBlockSignatureReasonCode::WeightMismatch,
                message: "weight overflow".into(),
            })?;
        }
        if total != self.sig_weight {
            return pq_reject(
                PqBlockSignatureReasonCode::WeightMismatch,
                "signature weight mismatch",
            );
        }
        Ok(total)
    }
    fn construct_bounded(root: Cell, budget: &dyn ConfigReadBudget) -> Result<Self> {
        // The original input may contain extra reachable cells ignored by a
        // dictionary decoder. Count the actual graph, not only parsed fields.
        bounded_signature_boc_size(&root, budget)?;
        let mut cell = SliceData::load_cell(root)?;
        if cell.get_next_byte()? != BLOCK_SIGNATURES_SIMPLEX_PQ_TAG {
            return pq_reject(
                PqBlockSignatureReasonCode::UnsupportedCarrier,
                "unsupported carrier",
            );
        }
        let validator_info = ValidatorBaseInfo::construct_from(&mut cell)?;
        let sig_count = u32::construct_from(&mut cell)?;
        if sig_count > PQ_SIGNATURE_MAX_SIGNERS {
            return pq_reject(
                PqBlockSignatureReasonCode::SignerCount,
                "signer count exceeds maximum",
            );
        }
        let sig_weight = u64::construct_from(&mut cell)?;
        let mut dictionary = PqBlockSignaturePairDict::default();
        dictionary.read_from(&mut cell)?;
        let mut signatures =
            signature_budget::vector::<PqBlockSignaturePair>(budget, sig_count as usize)?;
        dictionary.0.iterate_slices_bounded(budget, |mut key, mut value| {
            if key.get_next_int(16)? as usize != signatures.len() {
                return pq_reject(PqBlockSignatureReasonCode::DictionaryIndex, "dictionary index");
            }
            if signatures.len() >= sig_count as usize {
                return pq_reject(
                    PqBlockSignatureReasonCode::DictionaryExtraEntry,
                    "dictionary extra entry",
                );
            }
            let validator_id = UInt256::construct_from(&mut value)?;
            let algorithm_id = u16::construct_from(&mut value)?;
            if algorithm_id != MLDSA44_ALGORITHM_ID {
                return pq_reject(
                    PqBlockSignatureReasonCode::UnsupportedAlgorithm,
                    "unsupported algorithm",
                );
            }
            let signature = crate::pq_bytes::unpack_pq_bytes_bounded(
                &value.checked_drain_reference()?,
                PQ_SIGNATURE_BYTES,
                budget,
            )?;
            if signature.len() != PQ_SIGNATURE_BYTES {
                return pq_reject(PqBlockSignatureReasonCode::SignatureLength, "signature length");
            }
            if value.remaining_bits() != 0 || value.remaining_references() != 0 {
                return pq_reject(
                    PqBlockSignatureReasonCode::DictionaryIndex,
                    "dictionary value trailing data",
                );
            }
            signatures.push(PqBlockSignaturePair { validator_id, algorithm_id, signature });
            Ok(true)
        })?;
        if signatures.len() != sig_count as usize {
            return pq_reject(
                PqBlockSignatureReasonCode::DictionaryMissingEntry,
                "dictionary missing entry",
            );
        }
        let session_id = UInt256::construct_from(&mut cell)?;
        let slot = u32::construct_from(&mut cell)?;
        let candidate_data = cell.checked_drain_reference()?;
        if cell.remaining_bits() != 0 || cell.remaining_references() != 0 {
            return pq_reject(
                PqBlockSignatureReasonCode::UnsupportedCarrier,
                "carrier trailing data",
            );
        }
        let result = Self {
            validator_info,
            sig_count,
            sig_weight,
            signatures,
            session_id,
            slot,
            candidate_data,
        };
        result.validate_structure_bounded(budget)?;
        Ok(result)
    }
}
fn read_candidate_data_bounded(root: &Cell, budget: &dyn ConfigReadBudget) -> Result<Vec<u8>> {
    // Preserve the original chain-shape preflight before byte decoding.
    let mut probe = root.clone();
    for depth in 0..PQ_CANDIDATE_MAX_CHAIN {
        budget.step()?;
        crate::merkle_apply_budget::require_materialized(&probe)?;
        let mut slice = SliceData::load_cell_ref(&probe)?;
        if slice.remaining_references() > 1 {
            return pq_reject(
                PqBlockSignatureReasonCode::CandidateMultipleRefs,
                "multiple continuation refs",
            );
        }
        if slice.remaining_references() == 0 {
            break;
        }
        if depth + 1 == PQ_CANDIDATE_MAX_CHAIN {
            return pq_reject(PqBlockSignatureReasonCode::CandidateChainLength, "chain too long");
        }
        probe = slice.checked_drain_reference()?;
    }
    let mut out = signature_budget::vector::<u8>(budget, PQ_CANDIDATE_MAX_BYTES)?;
    let mut current = root.clone();
    for depth in 0..PQ_CANDIDATE_MAX_CHAIN {
        budget.step()?;
        crate::merkle_apply_budget::require_materialized(&current)?;
        if current.cell_type() != CellType::Ordinary || current.level() != 0 {
            return pq_reject(
                PqBlockSignatureReasonCode::CandidateTl,
                "non-ordinary candidate cell",
            );
        }
        let mut slice = SliceData::load_cell_ref(&current)?;
        if slice.remaining_bits() % 8 != 0 {
            return pq_reject(
                PqBlockSignatureReasonCode::CandidateNonByteAligned,
                "non-byte-aligned cell",
            );
        }
        if slice.remaining_references() > 1 {
            return pq_reject(
                PqBlockSignatureReasonCode::CandidateMultipleRefs,
                "multiple continuation refs",
            );
        }
        let count = slice.remaining_bits() / 8;
        if slice.remaining_references() == 1 && count != PQ_CANDIDATE_CHUNK_BYTES {
            return pq_reject(
                PqBlockSignatureReasonCode::CandidateNoncanonicalChunk,
                "noncanonical chunk size",
            );
        }
        if out.len() + count > PQ_CANDIDATE_MAX_BYTES {
            return pq_reject(PqBlockSignatureReasonCode::CandidateOversize, "oversize");
        }
        for _ in 0..count {
            out.push(slice.get_next_byte()?);
        }
        if slice.remaining_references() == 0 {
            if count == 0 && depth != 0 {
                return pq_reject(
                    PqBlockSignatureReasonCode::CandidateTrailingRef,
                    "trailing empty cell",
                );
            }
            validate_candidate_tl(&out)?;
            return Ok(out);
        }
        current = slice.checked_drain_reference()?;
    }
    pq_reject(PqBlockSignatureReasonCode::CandidateChainLength, "chain too long")
}

fn bounded_signature_boc_size(root: &Cell, budget: &dyn ConfigReadBudget) -> Result<usize> {
    use crate::merkle_apply_budget::{BudgetMap, BudgetStack, MerkleApplyBudget};
    struct Adapter<'a>(&'a dyn ConfigReadBudget);
    impl MerkleApplyBudget for Adapter<'_> {
        fn step(&self) -> Result<()> {
            self.0.step()
        }
        fn workspace(&self, n: usize) -> Result<()> {
            self.0.workspace(n)
        }
        fn new_cell(&self, n: usize) -> Result<()> {
            self.0.workspace(n)
        }
        fn max_depth(&self) -> u16 {
            u16::MAX
        }
    }
    crate::merkle_apply_budget::require_materialized(root)?;
    if root.repr_depth() > crate::MAX_SAFE_DEPTH {
        fail!("Signature BOC exceeds safe depth");
    }
    let b = Adapter(budget);
    let mut seen = BudgetMap::<()>::new(PQ_SIGNATURE_BOC_MAX_BYTES / 2 + 1);
    let mut stack = BudgetStack::new(PQ_SIGNATURE_BOC_MAX_BYTES / 2 + 1);
    stack.push(root.clone(), &b)?;
    let (mut data, mut refs) = (0usize, 0usize);
    while let Some(cell) = stack.pop() {
        budget.step()?;
        crate::merkle_apply_budget::require_materialized(&cell)?;
        if seen.get(&cell.repr_hash(), &b)?.is_some() {
            continue;
        }
        seen.insert(cell.repr_hash(), (), &b)?;
        data += 2 + cell.bit_length().div_ceil(8);
        refs += cell.references_count();
        if data > PQ_SIGNATURE_BOC_MAX_BYTES {
            return pq_reject(
                PqBlockSignatureReasonCode::CarrierOversize,
                "carrier exceeds hard maximum",
            );
        }
        for i in 0..cell.references_count() {
            stack.push(cell.reference(i)?, &b)?;
        }
    }
    let bytes = |n: usize| ((usize::BITS - n.leading_zeros()) as usize).div_ceil(8).max(1);
    let width = bytes(seen.len());
    let total = data + refs * width;
    // BocWriter::with_root uses no index, CRC, top or internal hashes.
    let serialized_size = 6 + 4 * width + bytes(total) + total;
    if serialized_size > PQ_SIGNATURE_BOC_MAX_BYTES {
        return pq_reject(
            PqBlockSignatureReasonCode::CarrierOversize,
            "carrier exceeds hard maximum",
        );
    }
    Ok(serialized_size)
}
impl BlockProof {
    pub fn construct_from_cell_bounded(root: Cell, budget: &dyn ConfigReadBudget) -> Result<Self> {
        budget.step()?;
        crate::merkle_apply_budget::require_materialized(&root)?;
        let mut cell = SliceData::load_cell(root)?;
        let tag = cell.get_next_byte()?;
        if tag != BLOCK_PROOF_TAG {
            fail!(Self::invalid_tag(tag as u32));
        }
        let proof_for = BlockIdExt::construct_from(&mut cell)?;
        let root = cell.checked_drain_reference()?;
        let signatures = if cell.get_next_bit()? {
            let signature_root = cell.checked_drain_reference()?;
            crate::merkle_apply_budget::require_materialized(&signature_root)?;
            let mut value = SliceData::load_cell_ref(&signature_root)?;
            let tag = value.clone().get_next_byte()?;
            Some(if tag == BLOCK_SIGNATURES_SIMPLEX_PQ_TAG {
                BlockSignaturesVariant::SimplexPq(BlockSignaturesSimplexPq::construct_bounded(
                    signature_root,
                    budget,
                )?)
            } else {
                BlockSignaturesVariant::construct_from(&mut value)?
            })
        } else {
            None
        };
        Ok(Self { proof_for, root, signatures })
    }
}

impl BlockSignaturesSimplex {
    pub fn bytes_to_cell_tree_bounded(bytes: &[u8], budget: &dyn ConfigReadBudget) -> Result<Cell> {
        if bytes.len() > Self::CELL_STRING_MAX_BYTES {
            fail!("String is too long (1)");
        }
        let depth = bytes.len().div_ceil(Self::CELL_STRING_BYTES_PER_CELL).max(1);
        if depth > Self::CELL_STRING_MAX_CHAIN {
            fail!("String is too long (2)");
        }
        let mut next = None;
        for index in (0..depth).rev() {
            budget.step()?;
            budget.workspace(crate::merkle_apply_budget::NEW_CELL_ALLOCATION)?;
            let start = index * Self::CELL_STRING_BYTES_PER_CELL;
            let end = (start + Self::CELL_STRING_BYTES_PER_CELL).min(bytes.len());
            let mut cell = BuilderData::new();
            cell.append_raw(&bytes[start..end], (end - start) * 8)?;
            if let Some(next) = next.take() {
                cell.checked_append_reference(next)?;
            }
            next = Some(cell.into_cell()?);
        }
        next.ok_or_else(|| crate::error!("Empty cell chain"))
    }
}
