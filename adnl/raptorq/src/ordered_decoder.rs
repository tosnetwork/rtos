// Copyright 2017-2020 Telegram Systems LLP
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Arrival-ordered single-block recovery using td/fec's inactivation and pivot policy.
//! Inconsistent equations can select different results under different solver policies.
use crate::{
    base::{intermediate_tuple, EncodingPacket, ObjectTransmissionInformation},
    constraint_matrix::{enc_indices, generate_constraint_matrix},
    encoder::SourceBlockEncoder,
    matrix::BinaryMatrix,
    octet::Octet,
    octets::{add_assign, fused_addassign_mul_scalar, mulassign_scalar},
    sparse_matrix::SparseBinaryMatrix,
    symbol::Symbol,
    systematic_constants::{
        calculate_p1, extended_source_block_symbols, num_hdpc_symbols, num_ldpc_symbols,
        num_lt_symbols, num_pi_symbols, systematic_index,
    },
};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec::Vec};
#[cfg(feature = "std")]
use std::{collections::BTreeMap, vec::Vec};

// The sparse adjacency and stable counting-sort updates match InactivationDecoding.cpp.
fn inactivation(
    rows: &[Vec<usize>],
    width: usize,
    active: usize,
) -> (usize, Vec<usize>, Vec<usize>) {
    let n = rows.len();
    let mut columns = vec![Vec::new(); active];
    let mut count = vec![0; n];
    let mut row_xor = vec![0; n];
    for (r, row) in rows.iter().enumerate() {
        for &c in row.iter().filter(|&&c| c < active) {
            columns[c].push(r);
            count[r] += 1;
            row_xor[r] ^= c;
        }
    }
    let mut offsets = vec![0; active + 2];
    for &c in &count {
        offsets[c + 1] += 1;
    }
    for i in 1..offsets.len() {
        offsets[i] += offsets[i - 1];
    }
    let mut insertion = offsets.clone();
    let mut sorted = vec![0; n];
    let mut position = vec![0; n];
    for r in 0..n {
        let i = insertion[count[r]];
        insertion[count[r]] += 1;
        sorted[i] = r;
        position[r] = i;
    }
    let mut used_rows = vec![false; n];
    let mut used_columns = vec![false; active];
    let mut p_rows = Vec::new();
    let mut p_columns = Vec::new();
    let mut inactive = Vec::new();
    while offsets[1] != n {
        let row = sorted[offsets[1]];
        let column = if count[row] == 1 {
            row_xor[row]
        } else {
            *rows[row]
                .iter()
                .filter(|&&c| c < active && !used_columns[c])
                .min_by_key(|&&c| columns[c].len())
                .unwrap()
        };
        p_rows.push(row);
        p_columns.push(column);
        let deactivate = if count[row] == 1 {
            vec![column]
        } else {
            rows[row].iter().copied().filter(|&c| c < active && !used_columns[c]).collect()
        };
        for c in deactivate {
            if c != column {
                inactive.push(c);
            }
            used_columns[c] = true;
            for &r in &columns[c] {
                if used_rows[r] {
                    continue;
                }
                let pos = position[r];
                let offset = offsets[count[r]];
                sorted.swap(pos, offset);
                position[sorted[pos]] = pos;
                position[sorted[offset]] = offset;
                offsets[count[r]] += 1;
                count[r] -= 1;
                row_xor[r] ^= c;
            }
        }
        used_rows[row] = true;
    }
    let side = p_rows.len();
    p_rows.extend((0..n).filter(|&r| !used_rows[r]));
    p_columns.extend(inactive.into_iter().rev());
    p_columns.extend(active..width);
    (side, p_rows, p_columns)
}

type Row = BTreeMap<usize, Octet>;
fn add_data(target: &mut [u8], source: &[u8], scalar: &Octet) {
    if *scalar == Octet::one() {
        add_assign(target, source);
    } else {
        fused_addassign_mul_scalar(target, source, scalar);
    }
}
fn add_row(target: &mut Row, source: &Row, scalar: &Octet) {
    for (&c, v) in source {
        let value =
            target.get(&c).cloned().unwrap_or_else(Octet::zero) + v.clone() * scalar.clone();
        if value == Octet::zero() {
            target.remove(&c);
        } else {
            target.insert(c, value);
        }
    }
}

/// Recover one unpartitioned block with arrival-ordered symbols and return a repair encoder.
/// The caller performs admission, first-duplicate handling and repair retention limits.
pub fn decode_ordered(
    config: &ObjectTransmissionInformation,
    packets: &[EncodingPacket],
) -> Option<(Vec<u8>, SourceBlockEncoder)> {
    let (data, encoder) = decode_ordered_with_encoder(config, packets, true)?;
    Some((data, encoder?))
}

/// Recover one block, retaining a repair encoder only when requested. With
/// `need_encoder == false`, the solved intermediate symbols are discarded after
/// reconstructing the data, as in td/fec's `try_decode(false)` receive path.
pub fn decode_ordered_with_encoder(
    config: &ObjectTransmissionInformation,
    packets: &[EncodingPacket],
    need_encoder: bool,
) -> Option<(Vec<u8>, Option<SourceBlockEncoder>)> {
    if config.source_blocks() != 1
        || config.sub_blocks() != 1
        || config.symbol_alignment() != 1
        || config.symbol_size() == 0
        || config.transfer_length() == 0
    {
        return None;
    }
    let size = config.symbol_size() as usize;
    let k = u32::try_from(config.transfer_length().div_ceil(size as u64)).ok()?;
    if k > 56403 || packets.len() < k as usize {
        return None;
    }
    let padded = extended_source_block_symbols(k);
    let s = num_ldpc_symbols(k) as usize;
    let h = num_hdpc_symbols(k) as usize;
    let w = num_lt_symbols(k) as usize;
    let mut ids = Vec::new();
    let mut d = vec![vec![0; size]; s];
    for packet in packets {
        if packet.payload_id().source_block_number() != 0 || packet.data().len() != size {
            return None;
        }
        let id = packet.payload_id().encoding_symbol_id();
        ids.push(if id < k { id } else { id + padded - k });
        d.push(packet.data().to_vec());
    }
    for id in k..padded {
        ids.push(id);
        d.push(vec![0; size]);
    }
    let (binary, hdpc) = generate_constraint_matrix::<SparseBinaryMatrix>(k, &ids);
    let width = binary.width();
    let upper = s + ids.len();
    let rows = (0..upper)
        .map(|r| {
            let r = if r < s { r } else { r + h };
            let mut row = binary
                .get_row_iter(r, 0, w)
                .filter_map(|(c, v)| (v != Octet::zero()).then_some(c))
                .collect::<Vec<_>>();
            row.extend(binary.query_non_zero_columns(r, w));
            row.sort_unstable();
            row
        })
        .collect::<Vec<_>>();
    let (side, p_rows, p_columns) = inactivation(&rows, width, w);
    let mut inverse = vec![0; width];
    for (i, &c) in p_columns.iter().enumerate() {
        inverse[c] = i;
    }
    let mut a = p_rows
        .iter()
        .map(|&r| rows[r].iter().map(|&c| (inverse[c], Octet::one())).collect::<Row>())
        .collect::<Vec<_>>();
    let mut data = p_rows.iter().map(|&r| d[r].clone()).collect::<Vec<_>>();
    for r in 0..h {
        a.push(
            (0..width)
                .filter_map(|c| {
                    let value = hdpc.get(r, c);
                    (value != Octet::zero()).then_some((inverse[c], value))
                })
                .collect(),
        );
        data.push(vec![0; size]);
    }
    // Inactivation leaves a triangular binary prefix. Its active-column adjacency
    // does not grow when eliminating pivots; only the inactive suffix gains entries.
    let mut adjacency = vec![Vec::new(); side];
    for (r, row) in a.iter().enumerate() {
        for &c in row.keys().take_while(|&&c| c < side) {
            adjacency[c].push(r);
        }
    }
    for i in 0..side {
        let pivot = a[i].clone();
        let value = data[i].clone();
        debug_assert_eq!(pivot.keys().filter(|&&c| c < side).copied().collect::<Vec<_>>(), vec![i]);
        for &r in &adjacency[i] {
            if r == i {
                continue;
            }
            if let Some(scalar) = a[r].get(&i).cloned() {
                add_row(&mut a[r], &pivot, &scalar);
                add_data(&mut data[r], &value, &scalar);
            }
        }
    }
    // Match GaussianElimination.cpp: first nonzero row in current permutation,
    // normalize, then eliminate from every other row, including surplus equations.
    let mut permutation = (0..a.len()).collect::<Vec<_>>();
    for col in side..width {
        let next = (col..a.len()).find(|&r| a[permutation[r]].contains_key(&col))?;
        permutation.swap(col, next);
        let row = permutation[col];
        let inverse = Octet::one() / a[row][&col].clone();
        for value in a[row].values_mut() {
            *value = value.clone() * inverse.clone();
        }
        if inverse != Octet::one() {
            mulassign_scalar(&mut data[row], &inverse);
        }
        let pivot = a[row].clone();
        let value = data[row].clone();
        for r in 0..a.len() {
            if r == row {
                continue;
            }
            if let Some(scalar) = a[r].get(&col).cloned() {
                add_row(&mut a[r], &pivot, &scalar);
                add_data(&mut data[r], &value, &scalar);
            }
        }
    }
    let mut intermediate = vec![Symbol::zero(size); width];
    for col in 0..width {
        intermediate[p_columns[col]] = Symbol::new(data[permutation[col]].clone());
    }
    let pi = num_pi_symbols(k);
    let p1 = calculate_p1(k, pi);
    let mut decoded = Vec::with_capacity(k as usize * size);
    for id in 0..k {
        let tuple = intermediate_tuple(id, w as u32, systematic_index(k), p1);
        let mut data = vec![0; size];
        for index in enc_indices(tuple, w as u32, pi, p1) {
            add_assign(&mut data, intermediate[index].as_bytes());
        }
        decoded.extend_from_slice(&data);
    }
    let encoder = need_encoder
        .then(|| SourceBlockEncoder::from_decoded(0, config, &decoded, Some(intermediate)));
    decoded.truncate(config.transfer_length() as usize);
    Some((decoded, encoder))
}
