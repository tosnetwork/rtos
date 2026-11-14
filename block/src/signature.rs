/*
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    blocks::BlockIdExt,
    define_HashmapE,
    error::BlockError,
    fail, hm_label,
    pq_bytes::{pack_pq_bytes, unpack_pq_bytes},
    read_single_root_boc,
    validators::{ValidatorBaseInfo, ValidatorDescr, MLDSA44_ALGORITHM_ID},
    BuilderData, Cell, CellType, Deserializable, Ed25519KeyOption, HashmapE, HashmapType,
    IBitstring, KeyOption, Result, Serializable, SliceData, UInt256, ZeroizingBytes,
    ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH,
};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    str::FromStr,
    sync::Arc,
};
use thiserror::Error;

/*
ed25519_signature#5 R:bits256 s:bits256 = CryptoSignatureSimple;
_ CryptoSignatureSimple = CryptoSignature;
certificate#4 temp_key:SigPubKey valid_since:uint32 valid_until:uint32 = Certificate;
signed_certificate$_ certificate:Certificate certificate_signature:CryptoSignature
  = SignedCertificate;
chained_signature#f signed_cert:^SignedCertificate temp_key_signature:CryptoSignatureSimple
  = CryptoSignature;
*/
///
/// CryptoSignature: a simple Ed25519 signature, or a chained signature made
/// with a temporary key that a signed certificate delegates. The certificate
/// signature is a CryptoSignature again, so chains nest.
///
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CryptoSignature {
    /// The simple signature; for a chained signature, the temporary-key one.
    signature: [u8; ED25519_SIGNATURE_LENGTH],
    signed_cert: Option<Box<SignedCertificate>>,
}

impl Default for CryptoSignature {
    fn default() -> Self {
        Self::with_bytes([0; ED25519_SIGNATURE_LENGTH])
    }
}

impl CryptoSignature {
    pub fn with_bytes(bytes: [u8; ED25519_SIGNATURE_LENGTH]) -> Self {
        Self { signature: bytes, signed_cert: None }
    }

    /// A chained signature: `temp_key_signature` made with the key that
    /// `signed_cert` delegates.
    pub fn chained(
        signed_cert: SignedCertificate,
        temp_key_signature: [u8; ED25519_SIGNATURE_LENGTH],
    ) -> Self {
        Self { signature: temp_key_signature, signed_cert: Some(Box::new(signed_cert)) }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self::with_bytes(bytes.try_into()?))
    }

    pub fn from_r_s_str(r: &str, s: &str) -> Result<Self> {
        let mut signature = Self::default();
        hex::decode_to_slice(r, &mut signature.signature[..ED25519_SIGNATURE_LENGTH / 2]).map_err(
            |err| BlockError::InvalidData(format!("error parsing `r` hex string: {}", err)),
        )?;
        hex::decode_to_slice(s, &mut signature.signature[ED25519_SIGNATURE_LENGTH / 2..]).map_err(
            |err| BlockError::InvalidData(format!("error parsing `s` hex string: {}", err)),
        )?;
        Ok(signature)
    }

    pub fn with_r_s(r: &[u8; 32], s: &[u8; 32]) -> Self {
        let mut signature = Self::default();
        signature.signature[..ED25519_SIGNATURE_LENGTH / 2].copy_from_slice(r);
        signature.signature[ED25519_SIGNATURE_LENGTH / 2..].copy_from_slice(s);
        signature
    }

    /// R and s of the simple signature; for a chained signature, of the
    /// temporary-key signature (check `is_chained` first).
    pub fn as_r_s_bytes(&self) -> (&[u8], &[u8]) {
        let r_bytes = &self.signature[..ED25519_SIGNATURE_LENGTH / 2];
        let s_bytes = &self.signature[ED25519_SIGNATURE_LENGTH / 2..];
        (r_bytes, s_bytes)
    }

    /// The simple signature; for a chained signature, the temporary-key
    /// signature, which is not a signature by the certifying key (check
    /// `is_chained` first).
    pub fn as_bytes(&self) -> &[u8; ED25519_SIGNATURE_LENGTH] {
        &self.signature
    }

    pub fn is_chained(&self) -> bool {
        self.signed_cert.is_some()
    }

    pub fn signed_certificate(&self) -> Option<&SignedCertificate> {
        self.signed_cert.as_deref()
    }

    /// Reads a CryptoSignatureSimple: tag #5 and the 512-bit signature.
    fn read_simple(slice: &mut SliceData) -> Result<[u8; ED25519_SIGNATURE_LENGTH]> {
        let tag = slice.get_next_int(4)? as u8;
        if tag != CRYPTO_SIGNATURE_TAG {
            fail!(Self::invalid_tag(tag as u32))
        }
        let mut signature = [0; ED25519_SIGNATURE_LENGTH];
        slice.get_next_bytes_to_slice(&mut signature)?;
        Ok(signature)
    }

    fn write_simple(
        signature: &[u8; ED25519_SIGNATURE_LENGTH],
        cell: &mut BuilderData,
    ) -> Result<()> {
        cell.append_bits(CRYPTO_SIGNATURE_TAG as usize, 4)?;
        cell.append_raw(signature, ED25519_SIGNATURE_LENGTH * 8)?;
        Ok(())
    }

    /// Writes a simple signature; a chained one is refused.
    fn write_simple_only(&self, cell: &mut BuilderData) -> Result<()> {
        if self.is_chained() {
            fail!(BlockError::InvalidData("a chained signature is not allowed here".to_string()))
        }
        Self::write_simple(&self.signature, cell)
    }

    /// Reads a simple signature; a chained one is refused.
    fn read_simple_only(slice: &mut SliceData) -> Result<Self> {
        Ok(Self::with_bytes(Self::read_simple(slice)?))
    }
}

impl FromStr for CryptoSignature {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self> {
        let mut signature = Self::default();
        hex::decode_to_slice(s, &mut signature.signature)?;
        Ok(signature)
    }
}

const CRYPTO_SIGNATURE_TAG: u8 = 0x5;
const CHAINED_SIGNATURE_TAG: u8 = 0xf;
const CERTIFICATE_TAG: u8 = 0x4;

/*
certificate#4 temp_key:SigPubKey valid_since:uint32 valid_until:uint32 = Certificate;
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Certificate {
    pub temp_key: SigPubKey,
    pub valid_since: u32,
    pub valid_until: u32,
}

/*
signed_certificate$_ certificate:Certificate certificate_signature:CryptoSignature
  = SignedCertificate;
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignedCertificate {
    pub certificate: Certificate,
    pub certificate_signature: CryptoSignature,
}

/// One signed-certificate cell of a chain: its certificate and the simple
/// part of its certificate signature.
struct CertificateLink {
    certificate: Certificate,
    signature: [u8; ED25519_SIGNATURE_LENGTH],
}

impl CertificateLink {
    fn write_cell(&self, next: Option<Cell>) -> Result<Cell> {
        let mut cell = BuilderData::new();
        cell.append_bits(CERTIFICATE_TAG as usize, 4)?;
        self.certificate.temp_key.write_to(&mut cell)?;
        cell.append_u32(self.certificate.valid_since)?;
        cell.append_u32(self.certificate.valid_until)?;
        if let Some(next) = next {
            cell.append_bits(CHAINED_SIGNATURE_TAG as usize, 4)?;
            cell.checked_append_reference(next)?;
        }
        CryptoSignature::write_simple(&self.signature, &mut cell)?;
        cell.into_cell()
    }
}

impl Serializable for CryptoSignature {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        let Some(first) = self.signed_cert.as_deref() else {
            return Self::write_simple(&self.signature, cell);
        };
        // Collect the chain and build its cells from the innermost one, so a
        // long chain does not grow the call stack.
        let mut links = Vec::new();
        let mut current = Some(first);
        while let Some(signed) = current {
            links.push(CertificateLink {
                certificate: signed.certificate.clone(),
                signature: signed.certificate_signature.signature,
            });
            current = signed.certificate_signature.signed_cert.as_deref();
        }
        let mut next = None;
        for link in links.iter().rev() {
            next = Some(link.write_cell(next)?);
        }
        let Some(cert_cell) = next else { fail!("empty certificate chain") };
        cell.append_bits(CHAINED_SIGNATURE_TAG as usize, 4)?;
        cell.checked_append_reference(cert_cell)?;
        Self::write_simple(&self.signature, cell)
    }
}

impl Deserializable for CryptoSignature {
    fn read_from(&mut self, slice: &mut SliceData) -> Result<()> {
        match slice.get_int(4)? as u8 {
            CRYPTO_SIGNATURE_TAG => {
                *self = Self::with_bytes(Self::read_simple(slice)?);
                Ok(())
            }
            CHAINED_SIGNATURE_TAG => {
                slice.move_by(4)?;
                let mut cert_cell = slice.checked_drain_reference()?;
                let temp_key_signature = Self::read_simple(slice)?;
                // Each referenced certificate cell is consumed exactly; the
                // chain is read iteratively (its length is bounded by the
                // cell depth limit).
                let mut links = Vec::new();
                loop {
                    if cert_cell.cell_type() != CellType::Ordinary {
                        fail!(BlockError::InvalidData(
                            "signed certificate is not an ordinary cell".to_string()
                        ))
                    }
                    let mut cert = SliceData::load_cell(cert_cell)?;
                    let tag = cert.get_next_int(4)? as u8;
                    if tag != CERTIFICATE_TAG {
                        fail!(BlockError::InvalidConstructorTag {
                            t: tag as u32,
                            s: "Certificate".to_string()
                        })
                    }
                    let certificate = Certificate {
                        temp_key: SigPubKey::construct_from(&mut cert)?,
                        valid_since: cert.get_next_u32()?,
                        valid_until: cert.get_next_u32()?,
                    };
                    let next = match cert.get_int(4)? as u8 {
                        CHAINED_SIGNATURE_TAG => {
                            cert.move_by(4)?;
                            Some(cert.checked_drain_reference()?)
                        }
                        _ => None,
                    };
                    let signature = Self::read_simple(&mut cert)?;
                    if !cert.is_empty_cell() {
                        fail!(BlockError::InvalidData(
                            "signed certificate cell is not consumed exactly".to_string()
                        ))
                    }
                    links.push(CertificateLink { certificate, signature });
                    match next {
                        Some(next) => cert_cell = next,
                        None => break,
                    }
                }
                let mut inner: Option<Box<SignedCertificate>> = None;
                while let Some(link) = links.pop() {
                    let certificate_signature =
                        Self { signature: link.signature, signed_cert: inner.take() };
                    inner = Some(Box::new(SignedCertificate {
                        certificate: link.certificate,
                        certificate_signature,
                    }));
                }
                *self = Self { signature: temp_key_signature, signed_cert: inner };
                Ok(())
            }
            tag => fail!(Self::invalid_tag(tag as u32)),
        }
    }
}

/*
sig_pair$_ node_id_short:bits256 sign:CryptoSignature = CryptoSignaturePair;
*/
///
/// CryptoSignaturePair
///
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CryptoSignaturePair {
    pub node_id_short: UInt256,
    pub sign: CryptoSignature,
}

impl CryptoSignaturePair {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_params(node_id_short: UInt256, sign: CryptoSignature) -> Self {
        CryptoSignaturePair { node_id_short, sign }
    }
}

// Block signature pairs take simple signatures only (the reference block
// signature set requires exactly 256 + 4 + 512 bits with tag #5 and no
// references), on reading and on writing.
impl Serializable for CryptoSignaturePair {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        self.node_id_short.write_to(cell)?;
        self.sign.write_simple_only(cell)?;
        Ok(())
    }
}

impl Deserializable for CryptoSignaturePair {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        self.node_id_short.read_from(cell)?;
        self.sign = CryptoSignature::read_simple_only(cell)?;
        Ok(())
    }
}

/*
ed25519_pubkey#8e81278a pubkey:bits256 = SigPubKey;
*/

///
/// SigPubKey
///
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SigPubKey([u8; ED25519_PUBLIC_KEY_LENGTH]);

const SIG_PUB_KEY_TAG: u32 = 0x8e81278a;

impl SigPubKey {
    pub fn with_bytes(bytes: [u8; ED25519_PUBLIC_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.as_ref().try_into()?))
    }

    pub fn key_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LENGTH] {
        self.as_bytes()
    }
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LENGTH] {
        &self.0
    }

    pub fn pub_key(&self) -> Arc<dyn KeyOption> {
        Ed25519KeyOption::<ZeroizingBytes>::from_public_key(&self.0)
    }

    pub fn key_id(&self) -> [u8; 32] {
        *self.pub_key().id().data()
    }

    // be careful here - we recreate public key object everytime
    /// Verifies a simple signature by this key. A chained signature is
    /// refused: its bytes are a temporary-key signature, not one by this key.
    pub fn verify_signature(&self, data: &[u8], signature: &CryptoSignature) -> bool {
        !signature.is_chained() && self.pub_key().verify(data, signature.as_bytes()).is_ok()
    }

    pub fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq<UInt256> for SigPubKey {
    fn eq(&self, other: &UInt256) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl FromStr for SigPubKey {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self> {
        let mut public_key = Self::default();
        hex::decode_to_slice(s, &mut public_key.0)?;
        Ok(public_key)
    }
}

impl AsRef<[u8]> for SigPubKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Serializable for SigPubKey {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        cell.append_u32(SIG_PUB_KEY_TAG)?;
        cell.append_raw(&self.0, ED25519_PUBLIC_KEY_LENGTH * 8)?;
        Ok(())
    }
}

impl Deserializable for SigPubKey {
    fn construct_from(slice: &mut SliceData) -> Result<Self> {
        let tag = slice.get_next_u32()?;
        if tag != SIG_PUB_KEY_TAG {
            fail!(Self::invalid_tag(tag))
        }
        let mut public_key = Self::default();
        slice.get_next_bytes_to_slice(&mut public_key.0)?;
        Ok(public_key)
    }
}

/*
  PROOFS
*/

/*
block_signatures_pure#_
    sig_count:uint32
    sig_weight:uint64
    signatures:(HashmapE 16 CryptoSignaturePair)
= BlockSignaturesPure;
*/

define_HashmapE! {CryptoSignaturePairDict, 16, CryptoSignaturePair}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockSignaturesPure {
    sig_count: u32,
    sig_weight: u64,
    signatures: CryptoSignaturePairDict,
}

impl BlockSignaturesPure {
    pub fn new() -> Self {
        Self::default()
    }
    /// New instance of BlockSignaturesPure
    pub fn with_weight(sig_weight: u64) -> Self {
        Self { sig_count: 0, sig_weight, signatures: CryptoSignaturePairDict::default() }
    }

    /// Get count of signatures
    pub fn count(&self) -> u32 {
        self.sig_count
    }

    /// Get weight
    pub fn weight(&self) -> u64 {
        self.sig_weight
    }

    pub fn set_weight(&mut self, weight: u64) {
        self.sig_weight = weight;
    }

    /// Add crypto signature pair to BlockSignaturesPure
    pub fn add_sigpair(&mut self, signature: CryptoSignaturePair) {
        self.signatures.set(&(self.sig_count as u16), &signature).unwrap();
        self.sig_count += 1;
    }

    pub fn signatures(&self) -> &HashmapE {
        &self.signatures.0
    }

    pub fn check_signatures(&self, validators_list: &[ValidatorDescr], data: &[u8]) -> Result<u64> {
        crate::validate_validator_list(validators_list)?;
        // Calc validators short ids
        let mut validators_map = HashMap::new();
        for vd in validators_list {
            validators_map.insert(vd.compute_node_id_short()?, vd);
        }

        // Check signatures
        let mut weight = 0;
        let mut used_keys = HashSet::new();
        self.signatures().iterate_slices(|ref mut _key, ref mut slice| {
            let sign = CryptoSignaturePair::construct_from(slice)?;
            if let Some(vd) = validators_map.get(&sign.node_id_short) {
                if !used_keys.insert(sign.node_id_short) {
                    fail!(BlockError::DuplicatedSignature)
                }
                if !vd.verify_signature(data, &sign.sign) {
                    fail!(BlockError::BadSignature)
                }
                weight = crate::checked_add_validator_weight(weight, vd.weight)?;
            } else {
                fail!("signature from an unknown validator");
            }
            Ok(true)
        })?;
        Ok(weight)
    }
}

impl Serializable for BlockSignaturesPure {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        self.sig_count.write_to(cell)?;
        self.sig_weight.write_to(cell)?;
        self.signatures.write_to(cell)?;
        Ok(())
    }
}

/// Most entries a classical (`#11`/`#12`) signature dictionary may hold.
pub const MAX_CLASSICAL_SIGNATURES: usize = 1024;
/// An entry is exactly `node_id_short:bits256`, the `ed25519_signature#5`
/// tag and `R:bits256 s:bits256`, with no references.
const CRYPTO_SIGNATURE_PAIR_BITS: usize = 256 + 4 + 256 + 256;

/// A signature dictionary has one encoding: the cell the serializer writes for
/// the parsed entries. A reader accepts any edge-label form (short, long,
/// same) that spells the same key bits, so the received root is compared with
/// a dictionary rebuilt from the decoded entries. An empty dictionary has no
/// root on either side.
fn is_canonical_dictionary_root(received: Option<&Cell>, canonical: Option<&Cell>) -> bool {
    match (received, canonical) {
        (None, None) => true,
        (Some(received), Some(canonical)) => received.repr_hash() == canonical.repr_hash(),
        _ => false,
    }
}

/// Decodes the classical dictionary entry at position `index`: its key must be
/// that position, and its value exactly one `CryptoSignaturePair`.
fn read_classical_signature_entry(
    key: &mut SliceData,
    value: &mut SliceData,
    index: usize,
) -> Result<CryptoSignaturePair> {
    if index >= MAX_CLASSICAL_SIGNATURES {
        fail!("signatures dict: more than {} entries", MAX_CLASSICAL_SIGNATURES)
    }
    let key = key.get_next_int(16)? as usize;
    if key != index {
        fail!("signatures dict: key {} where index {} was expected", key, index)
    }
    if value.remaining_bits() != CRYPTO_SIGNATURE_PAIR_BITS || value.remaining_references() != 0 {
        fail!(
            "signatures dict: entry {} has {} bits and {} references, expected exactly {} bits",
            index,
            value.remaining_bits(),
            value.remaining_references(),
            CRYPTO_SIGNATURE_PAIR_BITS
        )
    }
    CryptoSignaturePair::construct_from(value)
}

fn check_classical_signature_count(entries: usize, sig_count: u32) -> Result<()> {
    if entries != sig_count as usize {
        fail!("signatures dict: {} entries, declared sig_count {}", entries, sig_count)
    }
    Ok(())
}

impl Deserializable for BlockSignaturesPure {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        self.sig_count.read_from(cell)?;
        self.sig_weight.read_from(cell)?;
        self.signatures.read_from(cell)?;
        let mut canonical = CryptoSignaturePairDict::default();
        let mut entries = 0usize;
        self.signatures.iterate_slices_with_keys(|mut key, mut value| {
            let pair = read_classical_signature_entry(&mut key, &mut value, entries)?;
            // `entries` is below MAX_CLASSICAL_SIGNATURES, so it fits the key.
            canonical.set(&(entries as u16), &pair)?;
            entries += 1;
            Ok(true)
        })?;
        if !is_canonical_dictionary_root(self.signatures.0.data(), canonical.0.data()) {
            fail!("signatures dict: noncanonical dictionary encoding")
        }
        check_classical_signature_count(entries, self.sig_count)
    }
}

/*
block_signatures#11
    validator_info:ValidatorBaseInfo
    pure_signatures:BlockSignaturesPure
= BlockSignatures;
*/

///
/// BlockSignatures
///
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct BlockSignatures {
    pub validator_info: ValidatorBaseInfo,
    pub pure_signatures: BlockSignaturesPure,
}

impl BlockSignatures {
    /// Create new empty instance of BlockSignatures
    pub fn new() -> Self {
        Self::default()
    }

    /// Create new instance of BlockSignatures
    pub fn with_params(
        validator_info: ValidatorBaseInfo,
        pure_signatures: BlockSignaturesPure,
    ) -> Self {
        BlockSignatures { validator_info, pure_signatures }
    }
}

const BLOCK_SIGNATURES_TAG: u8 = 0x11;

impl Serializable for BlockSignatures {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        cell.append_u8(BLOCK_SIGNATURES_TAG)?;
        self.validator_info.write_to(cell)?;
        self.pure_signatures.write_to(cell)?;
        Ok(())
    }
}

impl Deserializable for BlockSignatures {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        let tag = cell.get_next_byte()?;
        if tag != BLOCK_SIGNATURES_TAG {
            fail!(Self::invalid_tag(tag as u32))
        }
        self.validator_info.read_from(cell)?;
        self.pure_signatures.read_from(cell)?;
        Ok(())
    }
}

/*
block_signatures_simplex#12
    validator_info:ValidatorBaseInfo
    pure_signatures:BlockSignaturesPure
    session_id:bits256
    slot:uint32
    candidate_data:^Cell
= BlockSignatures;

Simplex consensus signatures with verification context.
Contains all data needed to reconstruct the signed data for verification.

Reference: C++ signature-set.h BlockSignatureSetSimplex
*/

const BLOCK_SIGNATURES_SIMPLEX_TAG: u8 = 0x12;

/// BlockSignaturesSimplex (Simplex format, tag 0x12)
///
/// Contains signatures from Simplex consensus along with the context
/// needed to verify them. Unlike ordinary signatures which sign
/// `ton_blockId(root_hash, file_hash)`, Simplex signatures sign
/// `consensus.dataToSign(session_id, vote)` where vote is a
/// notarize or finalize vote containing the CandidateId.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockSignaturesSimplex {
    pub validator_info: ValidatorBaseInfo,
    pub pure_signatures: BlockSignaturesPure,
    /// Simplex session ID (256-bit)
    pub session_id: UInt256,
    /// Slot number in the consensus session
    pub slot: u32,
    /// CandidateHashData stored as a Cell tree (matches TL-B: candidate_data:^Cell)
    /// Contains raw TL-serialized bytes (no length prefix), possibly spanning multiple cells
    pub candidate_data: Cell,
    /// true = FinalizeVote, false = NotarizeVote
    pub is_final: bool,
}

impl Default for BlockSignaturesSimplex {
    fn default() -> Self {
        Self {
            validator_info: ValidatorBaseInfo::default(),
            pure_signatures: BlockSignaturesPure::default(),
            session_id: UInt256::default(),
            slot: 0,
            candidate_data: Cell::default(),
            is_final: false,
        }
    }
}

impl BlockSignaturesSimplex {
    /// Create new instance with candidate_data as bytes (converts to Cell internally)
    pub fn with_params(
        validator_info: ValidatorBaseInfo,
        pure_signatures: BlockSignaturesPure,
        session_id: UInt256,
        slot: u32,
        candidate_data: Cell,
        is_final: bool,
    ) -> Self {
        //let candidate_data = Self::bytes_to_cell_tree(&candidate_data_bytes)?;
        Self { validator_info, pure_signatures, session_id, slot, candidate_data, is_final }
    }

    // ========================================================================
    // Factory methods (match C++ create_simplex / create_simplex_approve)
    // ========================================================================

    /// Create new instance for FINALIZED signatures (is_final = true)
    ///
    /// Reference: C++ BlockSignatureSet::create_simplex() - signature-set.cpp
    /// Use this for signatures that will be stored in block proofs.
    pub fn new_finalize(
        validator_info: ValidatorBaseInfo,
        pure_signatures: BlockSignaturesPure,
        session_id: UInt256,
        slot: u32,
        candidate_data: Cell,
    ) -> Self {
        Self::with_params(validator_info, pure_signatures, session_id, slot, candidate_data, true)
    }

    /// Create new instance for NOTARIZED (approve) signatures (is_final = false)
    ///
    /// Reference: C++ BlockSignatureSet::create_simplex_approve() - signature-set.cpp
    /// Use this for approve/notarize signatures during consensus.
    /// These CANNOT be serialized to cell format.
    pub fn new_notarize(
        validator_info: ValidatorBaseInfo,
        pure_signatures: BlockSignaturesPure,
        session_id: UInt256,
        slot: u32,
        candidate_data: Cell,
    ) -> Self {
        Self::with_params(validator_info, pure_signatures, session_id, slot, candidate_data, false)
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Returns true if this is a finalized signature set
    pub fn is_final(&self) -> bool {
        self.is_final
    }

    /// Set validator info (used when creating block proof)
    pub fn set_validator_info(&mut self, validator_info: ValidatorBaseInfo) {
        self.validator_info = validator_info;
    }

    /// Get mutable reference to pure_signatures (used for updating weight)
    pub fn pure_signatures_mut(&mut self) -> &mut BlockSignaturesPure {
        &mut self.pure_signatures
    }

    /// Get candidate_data as bytes (extracts from Cell tree)
    pub fn candidate_data_bytes(&self) -> Result<Vec<u8>> {
        Self::cell_tree_to_bytes(&self.candidate_data)
    }

    // ========================================================================
    // CellString: matches C++ vm::CellString (crypto/vm/cells/CellString.cpp)
    //
    // Stores raw bytes into a cell chain WITHOUT length prefix.
    // Each cell holds up to 127 bytes (1016 bits, byte-aligned from 1023).
    // Remaining data goes into child cell via reference.
    // ========================================================================

    const CELL_STRING_MAX_BYTES: usize = 1024;
    const CELL_STRING_MAX_CHAIN: usize = 16;
    const CELL_STRING_BYTES_PER_CELL: usize = 127; // Cell::max_bits / 8

    /// Store bytes into cell chain (C++ vm::CellString::store)
    pub fn bytes_to_cell_tree(bytes: &[u8]) -> Result<Cell> {
        if bytes.len() > Self::CELL_STRING_MAX_BYTES {
            fail!("String is too long (1)");
        }
        let depth = bytes.len().div_ceil(Self::CELL_STRING_BYTES_PER_CELL).max(1);
        if depth > Self::CELL_STRING_MAX_CHAIN {
            fail!("String is too long (2)");
        }

        let head = bytes.len().min(Self::CELL_STRING_BYTES_PER_CELL);
        let mut builder = BuilderData::new();
        builder.append_raw(&bytes[..head], head * 8)?;
        if head < bytes.len() {
            builder.checked_append_reference(Self::bytes_to_cell_tree(&bytes[head..])?)?;
        }
        builder.into_cell()
    }

    /// Load bytes from cell chain (C++ vm::CellString::load)
    fn cell_tree_to_bytes(cell: &Cell) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut current = cell.clone();

        for _ in 0..Self::CELL_STRING_MAX_CHAIN {
            let mut slice = SliceData::load_cell_ref(&current)?;
            let bits = slice.remaining_bits();
            if bits % 8 != 0 {
                fail!("Size is not divisible by 8");
            }
            result.extend(slice.get_next_bytes(bits / 8)?);
            if result.len() > Self::CELL_STRING_MAX_BYTES {
                fail!("String is too long (1)");
            }
            if slice.remaining_references() == 0 {
                return Ok(result);
            }
            current = slice.checked_drain_reference()?;
        }
        fail!("String is too long (2)")
    }
}

impl Serializable for BlockSignaturesSimplex {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        if !self.is_final {
            // Match C++ behavior: approve/notar signatures must not be serialized into block proofs.
            fail!("cannot serialize approve simplex signatures to cell");
        }
        cell.append_u8(BLOCK_SIGNATURES_SIMPLEX_TAG)?;
        self.validator_info.write_to(cell)?;
        self.pure_signatures.write_to(cell)?;
        cell.append_raw(self.session_id.as_slice(), 256)?;
        cell.append_u32(self.slot)?;

        // Store candidate_data Cell as a reference
        cell.checked_append_reference(self.candidate_data.clone())?;
        Ok(())
    }
}

impl Deserializable for BlockSignaturesSimplex {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        let tag = cell.get_next_byte()?;
        if tag != BLOCK_SIGNATURES_SIMPLEX_TAG {
            fail!(Self::invalid_tag(tag as u32))
        }
        self.validator_info.read_from(cell)?;
        self.pure_signatures.read_from(cell)?;
        let mut session_id_bytes = [0u8; 32];
        cell.get_next_bytes_to_slice(&mut session_id_bytes)?;
        self.session_id = UInt256::from(session_id_bytes);
        self.slot = cell.get_next_u32()?;

        // Read candidate_data Cell from reference
        self.candidate_data = cell.checked_drain_reference()?;
        // In C++ only finalized simplex signature sets are serialized into block proofs.
        // The `final_` flag is not present in `block.tlb` cell schema.
        self.is_final = true;
        Ok(())
    }
}

const BLOCK_SIGNATURES_SIMPLEX_PQ_TAG: u8 = 0x13;
pub const PQ_SIGNATURE_BYTES: usize = 2420;
pub const PQ_SIGNATURE_MAX_SIGNERS: u32 = 400;
pub const PQ_SIGNATURE_BOC_MAX_BYTES: usize = 1 << 20;
const PQ_CANDIDATE_MAX_BYTES: usize = 1024;
const PQ_CANDIDATE_MAX_CHAIN: usize = 16;
const PQ_CANDIDATE_CHUNK_BYTES: usize = 127;

/// Stable, language-independent classification of a rejected `#13` carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PqBlockSignatureReasonCode {
    DuplicateValidatorId,
    UnsupportedAlgorithm,
    SignatureLength,
    NoncanonicalPqbytes,
    DictionaryIndex,
    DictionaryMissingEntry,
    DictionaryExtraEntry,
    NoncanonicalDictionary,
    CandidateOversize,
    CandidateNoncanonicalChunk,
    CandidateNonByteAligned,
    CandidateMultipleRefs,
    CandidateChainLength,
    CandidateTrailingRef,
    CandidateTl,
    SignerCount,
    UnknownValidatorId,
    ValidatorAlgorithmMismatch,
    WeightMismatch,
    UnsupportedCarrier,
    CarrierOversize,
}

impl PqBlockSignatureReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateValidatorId => "duplicate_validator_id",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::SignatureLength => "signature_length",
            Self::NoncanonicalPqbytes => "noncanonical_pqbytes",
            Self::DictionaryIndex => "dictionary_index",
            Self::DictionaryMissingEntry => "dictionary_missing_entry",
            Self::DictionaryExtraEntry => "dictionary_extra_entry",
            Self::NoncanonicalDictionary => "noncanonical_dictionary",
            Self::CandidateOversize => "candidate_oversize",
            Self::CandidateNoncanonicalChunk => "candidate_noncanonical_chunk",
            Self::CandidateNonByteAligned => "candidate_non_byte_aligned",
            Self::CandidateMultipleRefs => "candidate_multiple_refs",
            Self::CandidateChainLength => "candidate_chain_length",
            Self::CandidateTrailingRef => "candidate_trailing_ref",
            Self::CandidateTl => "candidate_tl",
            Self::SignerCount => "signer_count",
            Self::UnknownValidatorId => "unknown_validator_id",
            Self::ValidatorAlgorithmMismatch => "validator_algorithm_mismatch",
            Self::WeightMismatch => "weight_mismatch",
            Self::UnsupportedCarrier => "unsupported_carrier",
            Self::CarrierOversize => "carrier_oversize",
        }
    }
}

#[derive(Debug, Error)]
#[error("post-quantum block signatures [{code}]: {message}", code = .code.as_str())]
pub struct PqBlockSignatureError {
    pub code: PqBlockSignatureReasonCode,
    message: String,
}

fn pq_reject<T>(code: PqBlockSignatureReasonCode, message: impl Into<String>) -> Result<T> {
    Err(PqBlockSignatureError { code, message: message.into() }.into())
}

pub fn pq_block_signature_reason_code(error: &crate::Error) -> Option<PqBlockSignatureReasonCode> {
    error.downcast_ref::<PqBlockSignatureError>().map(|error| error.code)
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct PqBlockSignaturePair {
    pub validator_id: UInt256,
    pub algorithm_id: u16,
    pub signature: Vec<u8>,
}

impl PqBlockSignaturePair {
    /// Fixed-suite field validation, without membership or cryptographic checks.
    pub fn validate(&self) -> Result<()> {
        if self.algorithm_id != MLDSA44_ALGORITHM_ID {
            return pq_reject(
                PqBlockSignatureReasonCode::UnsupportedAlgorithm,
                "unsupported algorithm",
            );
        }
        if self.signature.len() != PQ_SIGNATURE_BYTES {
            return pq_reject(PqBlockSignatureReasonCode::SignatureLength, "signature length");
        }
        Ok(())
    }
}

impl Serializable for PqBlockSignaturePair {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        self.validate()?;
        self.validator_id.write_to(cell)?;
        self.algorithm_id.write_to(cell)?;
        cell.checked_append_reference(pack_pq_bytes(&self.signature, PQ_SIGNATURE_BYTES)?)?;
        Ok(())
    }
}

impl Deserializable for PqBlockSignaturePair {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        self.validator_id.read_from(cell)?;
        self.algorithm_id.read_from(cell)?;
        if self.algorithm_id != MLDSA44_ALGORITHM_ID {
            return pq_reject(
                PqBlockSignatureReasonCode::UnsupportedAlgorithm,
                "unsupported algorithm",
            );
        }
        let signature_cell = cell.checked_drain_reference()?;
        self.signature = match unpack_pq_bytes(&signature_cell, PQ_SIGNATURE_BYTES) {
            Ok(value) => value,
            Err(error) if error.to_string().contains("oversize") => {
                return pq_reject(PqBlockSignatureReasonCode::SignatureLength, error.to_string())
            }
            Err(error) => {
                return pq_reject(
                    PqBlockSignatureReasonCode::NoncanonicalPqbytes,
                    error.to_string(),
                )
            }
        };
        if self.signature.len() != PQ_SIGNATURE_BYTES {
            return pq_reject(PqBlockSignatureReasonCode::SignatureLength, "signature length");
        }
        Ok(())
    }
}

define_HashmapE! {PqBlockSignaturePairDict, 16, PqBlockSignaturePair}

/// Validator identity and financial weight used for structural `#13` validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqBlockValidatorWeight {
    pub validator_id: UInt256,
    pub algorithm_id: u16,
    pub weight: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct BlockSignaturesSimplexPq {
    pub validator_info: ValidatorBaseInfo,
    pub sig_count: u32,
    pub sig_weight: u64,
    pub signatures: Vec<PqBlockSignaturePair>,
    pub session_id: UInt256,
    pub slot: u32,
    pub candidate_data: Cell,
}

fn read_candidate_data(root: &Cell) -> Result<Vec<u8>> {
    // Establish the hard structural depth before checking the greedy chunk shape.
    // This matches the production C++ refusal order for an overlong chain.
    let mut probe = root.clone();
    for depth in 0..PQ_CANDIDATE_MAX_CHAIN {
        let slice = SliceData::load_cell_ref(&probe)?;
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
        let mut next = slice;
        probe = next.checked_drain_reference()?;
    }

    let mut bytes = Vec::new();
    let mut current = root.clone();
    for depth in 0..PQ_CANDIDATE_MAX_CHAIN {
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
        if bytes.len().checked_add(count).filter(|value| *value <= PQ_CANDIDATE_MAX_BYTES).is_none()
        {
            return pq_reject(PqBlockSignatureReasonCode::CandidateOversize, "oversize");
        }
        bytes.extend(slice.get_next_bytes(count)?);
        if slice.remaining_references() == 0 {
            if count == 0 && depth != 0 {
                return pq_reject(
                    PqBlockSignatureReasonCode::CandidateTrailingRef,
                    "trailing empty cell",
                );
            }
            validate_candidate_tl(&bytes)?;
            return Ok(bytes);
        }
        current = slice.checked_drain_reference()?;
    }
    pq_reject(PqBlockSignatureReasonCode::CandidateChainLength, "chain too long")
}

/// Validate the fixed CandidateHashData wire shape, without admitting its block
/// coordinates as a chain shard or authenticating the candidate.
pub fn validate_candidate_tl(bytes: &[u8]) -> Result<()> {
    let Some(tag) = bytes.get(..4) else {
        return pq_reject(PqBlockSignatureReasonCode::CandidateTl, "invalid TL");
    };
    let tag = u32::from_le_bytes(tag.try_into()?);
    let exact = match tag {
        0x8354_642d => 120,
        0x3f64_31f8 => {
            let Some(parent) = bytes.get(116..120) else {
                return pq_reject(PqBlockSignatureReasonCode::CandidateTl, "invalid TL");
            };
            match u32::from_le_bytes(parent.try_into()?) {
                0x22cb_cca9 => 120,
                0x1a4b_9af1 => {
                    // CandidateParent contains a boxed CandidateId (constructor,
                    // slot, hash); omitting its constructor would accept bare data.
                    if bytes.get(120..124) != Some(&[0x3f, 0xcd, 0x91, 0xb6][..]) {
                        return pq_reject(
                            PqBlockSignatureReasonCode::CandidateTl,
                            "invalid parent candidate ID",
                        );
                    }
                    160
                }
                _ => return pq_reject(PqBlockSignatureReasonCode::CandidateTl, "invalid TL"),
            }
        }
        _ => return pq_reject(PqBlockSignatureReasonCode::CandidateTl, "invalid TL"),
    };
    if bytes.len() != exact {
        return pq_reject(PqBlockSignatureReasonCode::CandidateTl, "invalid TL length");
    }
    Ok(())
}

impl BlockSignaturesSimplexPq {
    pub fn candidate_bytes(&self) -> Result<Vec<u8>> {
        read_candidate_data(&self.candidate_data)
    }
    /// Check signer membership, algorithm ids, and declared weight only.
    /// This does not cryptographically verify any signature.
    pub fn check_structural_membership_and_weight(
        &self,
        validators: &[PqBlockValidatorWeight],
    ) -> Result<u64> {
        self.check_membership_with_keys(validators, |_| Ok(()))
    }

    /// Structural carrier checks against supplied descriptors, including each
    /// signer's public-key commitment. This does not verify any signature.
    pub fn check_structural_validator_set(&self, validators: &[ValidatorDescr]) -> Result<u64> {
        let weights: Vec<_> = validators
            .iter()
            .map(|v| {
                Ok(PqBlockValidatorWeight {
                    validator_id: v.validator_id()?,
                    algorithm_id: match &v.key {
                        crate::ValidatorKey::Pq(key) => key.algorithm_id,
                        _ => 0,
                    },
                    weight: v.weight,
                })
            })
            .collect::<Result<_>>()?;
        self.check_membership_with_keys(&weights, |id| {
            let member = validators
                .iter()
                .find(|v| v.validator_id().is_ok_and(|key| &key == id))
                .ok_or_else(|| crate::error!("missing validator descriptor"))?;
            let crate::ValidatorKey::Pq(key) = &member.key else {
                fail!("validator is not post-quantum");
            };
            let derived = crate::try_derive_consensus_key_id(key.algorithm_id, &key.public_key)
                .ok_or_else(|| crate::error!("malformed validator public key"))?;
            if derived != key.key_id {
                fail!("validator key_id mismatch");
            }
            Ok(())
        })
    }

    fn check_membership_with_keys(
        &self,
        validators: &[PqBlockValidatorWeight],
        check_key: impl Fn(&UInt256) -> Result<()>,
    ) -> Result<u64> {
        if self.sig_count > PQ_SIGNATURE_MAX_SIGNERS
            || self.signatures.len() > PQ_SIGNATURE_MAX_SIGNERS as usize
        {
            return pq_reject(
                PqBlockSignatureReasonCode::SignerCount,
                "signer count exceeds maximum",
            );
        }
        if self.sig_count as usize != self.signatures.len() {
            return pq_reject(
                PqBlockSignatureReasonCode::DictionaryMissingEntry,
                "signature count mismatch",
            );
        }
        let mut member_ids = HashSet::new();
        for member in validators {
            if !member_ids.insert(&member.validator_id) {
                return pq_reject(
                    PqBlockSignatureReasonCode::DuplicateValidatorId,
                    "duplicate governing validator_id",
                );
            }
        }
        let mut signer_ids = HashSet::new();
        let mut total = 0u64;
        for signature in &self.signatures {
            if !signer_ids.insert(&signature.validator_id) {
                return pq_reject(
                    PqBlockSignatureReasonCode::DuplicateValidatorId,
                    "duplicate validator_id",
                );
            }

            if signature.algorithm_id != MLDSA44_ALGORITHM_ID {
                return pq_reject(
                    PqBlockSignatureReasonCode::UnsupportedAlgorithm,
                    "unsupported algorithm",
                );
            }
            if signature.signature.len() != PQ_SIGNATURE_BYTES {
                return pq_reject(PqBlockSignatureReasonCode::SignatureLength, "signature length");
            }
            let Some(validator) = validators
                .iter()
                .find(|validator| validator.validator_id == signature.validator_id)
            else {
                return pq_reject(
                    PqBlockSignatureReasonCode::UnknownValidatorId,
                    "unknown validator_id",
                );
            };
            if validator.algorithm_id != signature.algorithm_id {
                return pq_reject(
                    PqBlockSignatureReasonCode::ValidatorAlgorithmMismatch,
                    "validator algorithm mismatch",
                );
            }
            check_key(&signature.validator_id)?;
            total = total.checked_add(validator.weight).ok_or_else(|| PqBlockSignatureError {
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

    /// Parse and structurally check a PQ #13 carrier. No cryptographic
    /// signature verification occurs here; do not use this result to decide
    /// whether a proof establishes validator authority or finality.
    pub fn construct_from_pq_boc(
        bytes: &[u8],
        validators: &[PqBlockValidatorWeight],
    ) -> Result<Self> {
        let parsed = Self::parse_pq_boc(bytes)?;
        parsed.check_structural_membership_and_weight(validators)?;
        Ok(parsed)
    }

    /// Parse a PQ carrier against supplied descriptor commitments, without
    /// cryptographically verifying signatures or authenticating the supplied set.
    pub fn construct_from_pq_boc_with_validator_set(
        bytes: &[u8],
        validators: &[ValidatorDescr],
        catchain_seqno: u32,
    ) -> Result<Self> {
        if validators.is_empty()
            || !validators
                .iter()
                .all(|v| matches!(&v.key, crate::ValidatorKey::Pq(key) if key.algorithm_id != 0))
        {
            fail!("validator set has no admitted PQ carrier");
        }
        crate::checked_validator_weight_sum(validators.iter().map(|v| v.weight))?;
        let mut ids = HashSet::new();
        let mut keys = HashSet::new();
        for member in validators {
            if !ids.insert(member.validator_id()?) || !keys.insert(member.consensus_key_id()?) {
                fail!("duplicate governing validator identity");
            }
        }
        let parsed = Self::parse_pq_boc(bytes)?;
        if parsed.validator_info.catchain_seqno != catchain_seqno {
            fail!("catchain seqno mismatch");
        }
        if parsed.validator_info.validator_list_hash_short
            != crate::ValidatorSet::calc_subset_hash_short(validators, catchain_seqno)?
        {
            fail!("validator set hash mismatch");
        }
        parsed.check_structural_validator_set(validators)?;
        Ok(parsed)
    }

    fn parse_pq_boc(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > PQ_SIGNATURE_BOC_MAX_BYTES {
            return pq_reject(
                PqBlockSignatureReasonCode::CarrierOversize,
                "carrier exceeds hard maximum",
            );
        }
        let root = read_single_root_boc(bytes)?;
        if SliceData::load_cell_ref(&root)?.get_next_byte()? != BLOCK_SIGNATURES_SIMPLEX_PQ_TAG {
            return pq_reject(
                PqBlockSignatureReasonCode::UnsupportedCarrier,
                "unsupported carrier",
            );
        }
        let parsed = match BlockSignaturesVariant::construct_from_full_cell(root)? {
            BlockSignaturesVariant::SimplexPq(parsed) => parsed,
            _ => {
                return pq_reject(
                    PqBlockSignatureReasonCode::UnsupportedCarrier,
                    "unsupported carrier",
                )
            }
        };
        Ok(parsed)
    }
}

impl Serializable for BlockSignaturesSimplexPq {
    fn write_to(&self, destination: &mut BuilderData) -> Result<()> {
        let mut root = BuilderData::new();
        let cell = &mut root;
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
        let mut ids = HashSet::new();
        let mut dictionary = PqBlockSignaturePairDict::default();
        for (index, signature) in self.signatures.iter().enumerate() {
            if !ids.insert(signature.validator_id.clone()) {
                return pq_reject(
                    PqBlockSignatureReasonCode::DuplicateValidatorId,
                    "duplicate validator_id",
                );
            }
            dictionary.set(&(index as u16), signature)?;
        }
        read_candidate_data(&self.candidate_data)?;
        cell.append_u8(BLOCK_SIGNATURES_SIMPLEX_PQ_TAG)?;
        self.validator_info.write_to(cell)?;
        self.sig_count.write_to(cell)?;
        self.sig_weight.write_to(cell)?;
        dictionary.write_to(cell)?;
        self.session_id.write_to(cell)?;
        self.slot.write_to(cell)?;
        cell.checked_append_reference(self.candidate_data.clone())?;
        let root = root.into_cell()?;
        if crate::write_boc(&root)?.len() > PQ_SIGNATURE_BOC_MAX_BYTES {
            return pq_reject(
                PqBlockSignatureReasonCode::CarrierOversize,
                "carrier exceeds hard maximum",
            );
        }
        destination.checked_append_references_and_data(&SliceData::load_cell(root)?)?;
        Ok(())
    }
}

impl Deserializable for BlockSignaturesSimplexPq {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        let original = cell.clone().into_cell()?;
        if cell.get_next_byte()? != BLOCK_SIGNATURES_SIMPLEX_PQ_TAG {
            return pq_reject(
                PqBlockSignatureReasonCode::UnsupportedCarrier,
                "unsupported carrier",
            );
        }
        self.signatures.clear();
        self.validator_info.read_from(cell)?;
        self.sig_count.read_from(cell)?;
        if self.sig_count > PQ_SIGNATURE_MAX_SIGNERS {
            return pq_reject(
                PqBlockSignatureReasonCode::SignerCount,
                "signer count exceeds maximum",
            );
        }
        self.sig_weight.read_from(cell)?;
        let mut dictionary = PqBlockSignaturePairDict::default();
        dictionary.read_from(cell)?;
        let mut expected = 0u32;
        let mut ids = HashSet::new();
        dictionary.iterate_slices_with_keys(|mut key, mut value| {
            let index = key.get_next_int(16)? as u32;
            if index != expected {
                return pq_reject(PqBlockSignatureReasonCode::DictionaryIndex, "dictionary index");
            }
            if expected >= self.sig_count || expected >= PQ_SIGNATURE_MAX_SIGNERS {
                return pq_reject(
                    PqBlockSignatureReasonCode::DictionaryExtraEntry,
                    "dictionary extra entry",
                );
            }
            let signature = PqBlockSignaturePair::construct_from(&mut value)?;
            if value.remaining_bits() != 0 || value.remaining_references() != 0 {
                return pq_reject(
                    PqBlockSignatureReasonCode::DictionaryIndex,
                    "dictionary value trailing data",
                );
            }
            if !ids.insert(signature.validator_id.clone()) {
                return pq_reject(
                    PqBlockSignatureReasonCode::DuplicateValidatorId,
                    "duplicate validator_id",
                );
            }
            self.signatures.push(signature);
            expected = expected.checked_add(1).ok_or_else(|| PqBlockSignatureError {
                code: PqBlockSignatureReasonCode::DictionaryExtraEntry,
                message: "dictionary count overflow".into(),
            })?;
            Ok(true)
        })?;
        if expected < self.sig_count {
            return pq_reject(
                PqBlockSignatureReasonCode::DictionaryMissingEntry,
                "dictionary missing entry",
            );
        }
        if expected > self.sig_count {
            return pq_reject(
                PqBlockSignatureReasonCode::DictionaryExtraEntry,
                "dictionary extra entry",
            );
        }
        // Every entry is canonical on its own (fixed-width fields, strict
        // PQBytes); what is left is the shape of the dictionary itself.
        let mut canonical = PqBlockSignaturePairDict::default();
        for (index, signature) in self.signatures.iter().enumerate() {
            // `index` is below PQ_SIGNATURE_MAX_SIGNERS, so it fits the key.
            canonical.set(&(index as u16), signature)?;
        }
        if !is_canonical_dictionary_root(dictionary.0.data(), canonical.0.data()) {
            return pq_reject(
                PqBlockSignatureReasonCode::NoncanonicalDictionary,
                "noncanonical dictionary",
            );
        }
        self.session_id.read_from(cell)?;
        self.slot.read_from(cell)?;
        self.candidate_data = cell.checked_drain_reference()?;
        read_candidate_data(&self.candidate_data)?;
        if cell.remaining_bits() != 0 || cell.remaining_references() != 0 {
            return pq_reject(
                PqBlockSignatureReasonCode::UnsupportedCarrier,
                "carrier trailing data",
            );
        }
        // After bounded structural parsing, the reachable graph is bounded too.
        if crate::write_boc(&original)?.len() > PQ_SIGNATURE_BOC_MAX_BYTES {
            return pq_reject(
                PqBlockSignatureReasonCode::CarrierOversize,
                "carrier exceeds hard maximum",
            );
        }
        Ok(())
    }
}

/// Block-signature carrier variants: ordinary, Simplex, and Simplex PQ.
///
/// The PQ variant provides structural decoding and declared-weight checks in
/// this crate, not cryptographic verification. In particular, it has no
/// `check_signatures()` path here and cannot establish authority or finality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockSignaturesVariant {
    /// Catchain/validator-session signatures (tag 0x11)
    Ordinary(BlockSignatures),
    /// Simplex consensus signatures (tag 0x12)
    Simplex(BlockSignaturesSimplex),
    /// Simplex post-quantum signatures (tag 0x13)
    SimplexPq(BlockSignaturesSimplexPq),
}

impl Default for BlockSignaturesVariant {
    fn default() -> Self {
        Self::Ordinary(BlockSignatures::default())
    }
}

impl BlockSignaturesVariant {
    /// Declared metadata only; neither count nor weight authenticates this carrier.
    pub fn declared_signature_count(&self) -> u32 {
        match self {
            Self::Ordinary(s) => s.pure_signatures.count(),
            Self::Simplex(s) => s.pure_signatures.count(),
            Self::SimplexPq(s) => s.sig_count,
        }
    }

    pub fn declared_signature_weight(&self) -> u64 {
        match self {
            Self::Ordinary(s) => s.pure_signatures.weight(),
            Self::Simplex(s) => s.pure_signatures.weight(),
            Self::SimplexPq(s) => s.sig_weight,
        }
    }

    /// Get pure signatures from either pre-PQ variant; the PQ variant has no CryptoSignature view.
    pub fn pure_signatures(&self) -> Result<&BlockSignaturesPure> {
        match self {
            Self::Ordinary(s) => Ok(&s.pure_signatures),
            Self::Simplex(s) => Ok(&s.pure_signatures),
            Self::SimplexPq(_) => fail!("post-quantum signatures have no CryptoSignature view"),
        }
    }

    /// Get mutable pure signatures
    pub fn pure_signatures_mut(&mut self) -> Result<&mut BlockSignaturesPure> {
        match self {
            Self::Ordinary(s) => Ok(&mut s.pure_signatures),
            Self::Simplex(s) => Ok(&mut s.pure_signatures),
            Self::SimplexPq(_) => fail!("post-quantum signatures have no CryptoSignature view"),
        }
    }

    /// Get validator info (common to all three variants)
    pub fn validator_info(&self) -> &ValidatorBaseInfo {
        match self {
            Self::Ordinary(s) => &s.validator_info,
            Self::Simplex(s) => &s.validator_info,
            Self::SimplexPq(s) => &s.validator_info,
        }
    }

    /// Get mutable validator info
    pub fn validator_info_mut(&mut self) -> &mut ValidatorBaseInfo {
        match self {
            Self::Ordinary(s) => &mut s.validator_info,
            Self::Simplex(s) => &mut s.validator_info,
            Self::SimplexPq(s) => &mut s.validator_info,
        }
    }

    /// Create Ordinary variant from existing BlockSignatures
    pub fn from_ordinary(sigs: BlockSignatures) -> Self {
        Self::Ordinary(sigs)
    }

    /// Create Simplex variant from existing BlockSignaturesSimplex
    pub fn from_simplex(sigs: BlockSignaturesSimplex) -> Self {
        Self::Simplex(sigs)
    }

    pub fn from_simplex_pq(sigs: BlockSignaturesSimplexPq) -> Self {
        Self::SimplexPq(sigs)
    }

    /// Returns true if this is an Ordinary variant
    pub fn is_ordinary(&self) -> bool {
        matches!(self, Self::Ordinary(_))
    }

    /// Returns true if this is a Simplex variant
    pub fn is_simplex(&self) -> bool {
        matches!(self, Self::Simplex(_) | Self::SimplexPq(_))
    }

    /// Get as Ordinary variant if applicable
    pub fn as_ordinary(&self) -> Option<&BlockSignatures> {
        match self {
            Self::Ordinary(s) => Some(s),
            Self::Simplex(_) => None,
            Self::SimplexPq(_) => None,
        }
    }

    /// Get as Simplex variant if applicable
    pub fn as_simplex(&self) -> Option<&BlockSignaturesSimplex> {
        match self {
            Self::Ordinary(_) => None,
            Self::Simplex(s) => Some(s),
            Self::SimplexPq(_) => None,
        }
    }

    pub fn as_simplex_pq(&self) -> Option<&BlockSignaturesSimplexPq> {
        match self {
            Self::SimplexPq(s) => Some(s),
            _ => None,
        }
    }
}

impl Serializable for BlockSignaturesVariant {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        match self {
            Self::Ordinary(s) => s.write_to(cell),
            Self::Simplex(s) => s.write_to(cell),
            Self::SimplexPq(s) => s.write_to(cell),
        }
    }
}

impl Deserializable for BlockSignaturesVariant {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        let tag = cell.get_next_byte()?;
        match tag {
            BLOCK_SIGNATURES_TAG => {
                let mut sigs = BlockSignatures::default();
                sigs.validator_info.read_from(cell)?;
                sigs.pure_signatures.read_from(cell)?;
                *self = Self::Ordinary(sigs);
            }
            BLOCK_SIGNATURES_SIMPLEX_TAG => {
                let mut sigs = BlockSignaturesSimplex::default();
                sigs.validator_info.read_from(cell)?;
                sigs.pure_signatures.read_from(cell)?;
                let mut session_id_bytes = [0u8; 32];
                cell.get_next_bytes_to_slice(&mut session_id_bytes)?;
                sigs.session_id = UInt256::from(session_id_bytes);
                sigs.slot = cell.get_next_u32()?;
                // Read candidate_data Cell from reference
                sigs.candidate_data = cell.checked_drain_reference()?;
                // See comment in BlockSignaturesSimplex::read_from
                sigs.is_final = true;
                *self = Self::Simplex(sigs);
            }
            BLOCK_SIGNATURES_SIMPLEX_PQ_TAG => {
                let mut prefixed = BuilderData::new();
                prefixed.append_u8(tag)?;
                prefixed.checked_append_references_and_data(cell)?;
                *self = Self::SimplexPq(BlockSignaturesSimplexPq::construct_from_full_cell(
                    prefixed.into_cell()?,
                )?);
                cell.clear_all_bits();
                cell.clear_all_references();
            }
            _ => fail!(BlockSignatures::invalid_tag(tag as u32)),
        }
        Ok(())
    }
}

/*
block_proof#c3
    proof_for:BlockIdExt
    root:^Cell
    signatures:(Maybe ^BlockSignaturesVariant)
= BlockProof;
*/

///
/// BlockProof
///
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct BlockProof {
    pub proof_for: BlockIdExt,
    pub root: Cell,
    pub signatures: Option<BlockSignaturesVariant>,
}

impl BlockProof {
    /// Create new empty instance of BlockProof
    pub fn new() -> Self {
        Self::default()
    }

    /// Create new instance of BlockProof with variant signatures
    pub fn with_params(
        proof_for: BlockIdExt,
        root: Cell,
        signatures: Option<BlockSignaturesVariant>,
    ) -> Self {
        BlockProof { proof_for, root, signatures }
    }

    /// Create new instance of BlockProof with ordinary (catchain) signatures
    ///
    /// Convenience constructor for creating proofs with standard BlockSignatures.
    pub fn with_ordinary_signatures(
        proof_for: BlockIdExt,
        root: Cell,
        signatures: Option<BlockSignatures>,
    ) -> Self {
        BlockProof { proof_for, root, signatures: signatures.map(BlockSignaturesVariant::Ordinary) }
    }
}

const BLOCK_PROOF_TAG: u8 = 0xC3;

impl Serializable for BlockProof {
    fn write_to(&self, cell: &mut BuilderData) -> Result<()> {
        cell.append_u8(BLOCK_PROOF_TAG)?;
        self.proof_for.write_to(cell)?;
        cell.checked_append_reference(self.root.clone())?;
        if let Some(s) = self.signatures.as_ref() {
            cell.append_bit_one()?;
            cell.checked_append_reference(s.serialize()?)?;
        } else {
            cell.append_bit_zero()?;
        }
        Ok(())
    }
}

impl Deserializable for BlockProof {
    fn read_from(&mut self, cell: &mut SliceData) -> Result<()> {
        let tag = cell.get_next_byte()?;
        if tag != BLOCK_PROOF_TAG {
            fail!(Self::invalid_tag(tag as u32))
        }
        self.proof_for.read_from(cell)?;
        self.root = cell.checked_drain_reference()?;
        self.signatures = if cell.get_next_bit()? {
            Some(BlockSignaturesVariant::construct_from_reference(cell)?)
        } else {
            None
        };
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/test_signature.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/test_pq_block_signature_vectors.rs"]
mod pq_tests;

include!("signature_bounded.rs");

#[cfg(test)]
#[path = "tests/test_signature_bounded.rs"]
mod bounded_tests;

#[cfg(test)]
#[path = "tests/test_signature_dictionary_canonical.rs"]
mod dictionary_canonical_tests;
