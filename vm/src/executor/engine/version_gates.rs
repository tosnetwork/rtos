// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::executor::pq::{
    PQ_FALCON512_MIN_VERSION, PQ_LMS_FEE_HASH_MIN_VERSION, PQ_MLDSA44_MIN_VERSION,
    PQ_SUITE_MIN_VERSION,
};
use rtos_block::{Result, SliceData};

/// CP0 registration gates, before operand decoding and instruction gas.
/// The opcode lookup pads short code with zeroes to 24 bits. In particular,
/// a disabled registration can be selected even when its operands are truncated.
/// Unknown ranges remain the dispatcher's responsibility.
pub(super) fn registration(code: &SliceData) -> Result<Option<(u32, usize)>> {
    let bits = code.remaining_bits().min(24);
    if bits == 0 {
        return Ok(None);
    }
    let opcode = (code.get_int(bits)? as u32) << (24 - bits);
    Ok(match opcode {
        // RIST255_QVALIDATE, RIST255_QADD, RIST255_QSUB, RIST255_QMUL, RIST255_QMULBASE.
        0xb7f921..=0xb7f925 => Some((4, 24)),
        // BTOS.
        0xcf5000..=0xcf50ff => Some((12, 16)),
        // CLEVEL, CLEVELMASK, CHASHI, CDEPTHI, CHASHIX, CDEPTHIX.
        0xd76600..=0xd771ff => Some((6, 16)),
        // RUNVM.
        0xdb4000..=0xdb4fff => Some((4, 24)),
        // RUNVMX.
        0xdb5000..=0xdb50ff => Some((4, 16)),
        // SETCONTCTRMANY.
        0xede300..=0xede3ff => Some((9, 24)),
        // SETCONTCTRMANYX.
        0xede400..=0xede4ff => Some((9, 16)),
        // GASCONSUMED.
        0xf80700..=0xf807ff => Some((4, 16)),
        // PREVMCBLOCKS, PREVKEYBLOCK.
        0xf83400..=0xf83401 => Some((4, 24)),
        // PREVMCBLOCKS_100.
        0xf83402..=0xf83402 => Some((9, 24)),
        // GLOBALID.
        0xf83500..=0xf835ff => Some((4, 16)),
        // GETGASFEE, GETSTORAGEFEE, GETFORWARDFEE, GETPRECOMPILEDGAS, GETORIGINALFWDFEE, GETGASFEESIMPLE, GETFORWARDFEESIMPLE.
        0xf83600..=0xf83cff => Some((6, 16)),
        // GETEXTRABALANCE.
        0xf88000..=0xf880ff => Some((10, 16)),
        // GETPARAMLONG, INMSGPARAMS, GETPARAMLONG.
        0xf88100..=0xf881fe => Some((11, 24)),
        // INMSG_BOUNCE, INMSG_BOUNCED, INMSG_SRC, INMSG_FWDFEE, INMSG_LT, INMSG_UTIME, INMSG_ORIGVALUE, INMSG_VALUE, INMSG_VALUEEXTRA, INMSG_STATEINIT, INMSGPARAM.
        0xf89000..=0xf89fff => Some((11, 16)),
        // SHA256C.
        0xf90300..=0xf903ff => Some((14, 16)),
        // HASH_EXT.
        0xf90400..=0xf907ff => Some((4, 24)),
        // ECRECOVER.
        0xf91200..=0xf912ff => Some((4, 16)),
        // SECP256K1_XONLY_PUBKEY_TWEAK_ADD.
        0xf91300..=0xf913ff => Some((9, 16)),
        // P256_CHKSIGNU, P256_CHKSIGNS.
        0xf91400..=0xf915ff => Some((4, 16)),
        // HASHBU.
        0xf91600..=0xf916ff => Some((12, 16)),
        // RIST255_FROMHASH, RIST255_VALIDATE, RIST255_ADD, RIST255_SUB, RIST255_MUL, RIST255_MULBASE, RIST255_PUSHL.
        0xf92000..=0xf926ff => Some((4, 16)),
        // BLS_VERIFY, BLS_AGGREGATE, BLS_FASTAGGREGATEVERIFY, BLS_AGGREGATEVERIFY.
        0xf93000..=0xf93003 => Some((4, 24)),
        // BLS_G1_ADD, BLS_G1_SUB, BLS_G1_NEG, BLS_G1_MUL, BLS_G1_MULTIEXP, BLS_G1_ZERO, BLS_MAP_TO_G1, BLS_G1_INGROUP, BLS_G1_ISZERO.
        0xf93010..=0xf93018 => Some((4, 24)),
        // BLS_G2_ADD, BLS_G2_SUB, BLS_G2_NEG, BLS_G2_MUL, BLS_G2_MULTIEXP, BLS_G2_ZERO, BLS_MAP_TO_G2, BLS_G2_INGROUP, BLS_G2_ISZERO.
        0xf93020..=0xf93028 => Some((4, 24)),
        // BLS_PAIRING, BLS_PUSHR.
        0xf93030..=0xf93031 => Some((4, 24)),
        // PQCHECKSIG_MLDSA44.
        0xf93100..=0xf93100 => Some((PQ_MLDSA44_MIN_VERSION, 24)),
        // PQCHECKSIG_FALCON512_PADDED.
        0xf93101..=0xf93101 => Some((PQ_FALCON512_MIN_VERSION, 24)),
        // PQCHECKSIG_SUITE.
        0xf93102..=0xf93102 => Some((PQ_SUITE_MIN_VERSION, 24)),
        // LMSCHECKFEEHASH.
        0xf93103..=0xf93103 => Some((PQ_LMS_FEE_HASH_MIN_VERSION, 24)),
        // POSEIDON2_PERM8, POSEIDON2_HASH7, POSEIDON2_PATH7.
        0xf93200..=0xf93202 => Some((16, 24)),
        // LDSTDADDR, LDSTDADDRQ.
        0xfa4800..=0xfa49ff => Some((12, 16)),
        // LDOPTSTDADDR, LDOPTSTDADDRQ, STSTDADDR, STSTDADDRQ, STOPTSTDADDR, STOPTSTDADDRQ.
        0xfa5000..=0xfa55ff => Some((12, 16)),
        // SENDMSG.
        0xfb0800..=0xfb08ff => Some((4, 16)),
        _ => None,
    })
}
