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
use crate::network::full_node_overlay_client::FullNodeOverlayClient;
use rtos_block::{fail, BlockIdExt, BocReader, Result};
use std::io::{Cursor, Seek, SeekFrom, Write};
use storage::types::PersistentStatePartId;

/// Persistent states are downloaded in parts of this size.
const PART_SIZE: usize = 1 << 21;
/// Transport attempts for one slice before the download attempt ends.
const SLICE_TRANSPORT_ATTEMPTS: u32 = 30;

/// A downloaded chunk is complete only after every byte reaches its writer.
/// This boundary does not claim that the destination has been synced to disk.
fn append_downloaded_chunk(dest: &mut impl Write, bytes: &[u8]) -> Result<usize> {
    dest.write_all(bytes)?;
    Ok(bytes.len())
}

#[cfg(test)]
#[path = "../tests/test_state_chunk_write.rs"]
mod chunk_write_tests;

#[allow(clippy::too_many_arguments)]
pub async fn download_pss_part<T: Write + Seek>(
    id: &PersistentStatePartId,
    master_id: &BlockIdExt,
    dest: &mut T,
    overlay: &FullNodeOverlayClient,
    mut attempts: Option<usize>,
    check_stop: &(dyn Fn() -> Result<()> + Sync + Send),
) -> Result<(usize, usize)> {
    if id.block_id().seq_no == 0 {
        fail!("download_pss_part: zerostate is not supported");
    }

    // Check
    let (peer, size) = loop {
        check_stop()?;
        if let Some(remained) = attempts.as_mut() {
            if *remained == 0 {
                fail!("download_pss_part: can't find peer for {}", id)
            }
            *remained -= 1;
        }
        match overlay.check_persistent_state(id, master_id).await {
            Err(e) => log::warn!("download_pss_part prepare {}: {}", id, e),
            Ok(None) => log::warn!("download_pss_part {} not found!", id),
            Ok(Some(p)) => break p,
        }
        futures_timer::Delay::new(std::time::Duration::from_millis(100)).await;
    };

    let fetch = |offset: usize, max_size: usize, attempt: u32| {
        let peer = peer.clone();
        async move {
            overlay
                .download_persistent_state_part_bounded(
                    id,
                    master_id,
                    offset,
                    max_size,
                    &peer,
                    attempt,
                    adnl::QueryResponseLimits { wire_bytes: max_size, decoded_bytes: max_size },
                )
                .await
        }
    };
    download_slices(id, size, dest, check_stop, fetch).await
}

/// Downloads the parts of a persistent state of `size` advertised bytes into
/// `dest`, from its current end: parts of PART_SIZE, the last one bounded by
/// the advertised size, each from `fetch(offset, size, transport attempt)`.
pub(crate) async fn download_slices<T, F, Fut>(
    id: &PersistentStatePartId,
    size: usize,
    dest: &mut T,
    check_stop: &(dyn Fn() -> Result<()> + Sync + Send),
    mut fetch: F,
) -> Result<(usize, usize)>
where
    T: Write + Seek,
    F: FnMut(usize, usize, u32) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    // Download: parts of PART_SIZE, the last one bounded by the advertised
    // size, all from the peer that advertised it. A part longer or shorter
    // than requested ends the attempt, as does any failed request.
    let now = std::time::Instant::now();
    let mut offset = dest.seek(SeekFrom::End(0))? as usize;
    if offset > size {
        fail!("download_pss_part {}: {} bytes stored, {} advertised", id, offset, size);
    }
    let mut part = 0;
    let mut cells_count = 0;

    log::info!("download_pss_part: starting from offset {}, id: {}, size: {}", offset, id, size);

    while offset < size {
        check_stop()?;
        let max_size = PART_SIZE.min(size - offset);
        // The reference gives a slice 20 s. RLDP here has no per-query
        // deadline: its transfer timeout follows the peer's roundtrip, so a
        // slice that outlives it is asked again from the same peer, with the
        // allowance growing on every attempt. An answer above the requested
        // size ends the attempt at once.
        let mut transport_attempt = 0u32;
        let next_bytes = loop {
            check_stop()?;
            match fetch(offset, max_size, transport_attempt).await {
                Ok(bytes) => break bytes,
                Err(e) if e.downcast_ref::<adnl::ResponseLimitExceeded>().is_some() => {
                    fail!(
                        "download_pss_part {}: part at {} exceeds {} bytes: {}",
                        id,
                        offset,
                        max_size,
                        e
                    )
                }
                Err(e) => {
                    transport_attempt = transport_attempt.saturating_add(1);
                    if transport_attempt > SLICE_TRANSPORT_ATTEMPTS {
                        fail!("download_pss_part {} at {}: {}", id, offset, e);
                    }
                    log::warn!(
                        "download_pss_part {} at {}: {}, attempt {}",
                        id,
                        offset,
                        e,
                        transport_attempt
                    );
                    futures_timer::Delay::new(std::time::Duration::from_millis(100)).await;
                }
            }
        };
        if next_bytes.len() > max_size {
            fail!(
                "download_pss_part {}: part at {} is {} bytes, {} requested",
                id,
                offset,
                next_bytes.len(),
                max_size
            );
        }
        if next_bytes.len() < max_size {
            fail!(
                "download_pss_part {}: stream ended at {} of {} advertised bytes",
                id,
                offset.saturating_add(next_bytes.len()),
                size
            );
        }
        if offset == 0 {
            let (boc_header, _) = BocReader::new().read_header(&mut Cursor::new(&next_bytes))?;
            cells_count = boc_header.cells_count;
            if cells_count == 0 {
                fail!("download_pss_part: got header with cells_count == 0");
            }
        }
        let len = append_downloaded_chunk(dest, &next_bytes)?;
        offset = offset.saturating_add(len);
        if part % 10 == 0 {
            log::info!(
                "download_pss_part {}: downloaded: {}% ({}/{})",
                id,
                (offset * 100) / size,
                offset,
                size
            );
        }
        part += 1;
    }
    log::info!(
        "download_pss_part {}: DONE in {:#?}, total length is {}",
        id,
        now.elapsed(),
        offset
    );

    Ok((offset, cells_count))
}
