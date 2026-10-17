// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Included in session_runtime; does not expose a constructor for private fields.
impl AuthenticatedSessionRuntime {
    pub fn from_decoded_config_bounded(
        pin: SessionNetworkPin,
        config: &rtos_block::DecodedSessionConfig,
        coordinates: SessionCoordinates<'_>,
        mut committee: Vec<ValidatorDescr>,
        local_adnl: PublicKeyHash,
        budget: &dyn rtos_block::config_read_budget::ConfigReadBudget,
    ) -> Result<Self> {
        use rtos_block::config_read_budget as cb;
        if !pin.zerostate.shard().is_masterchain()
            || pin.zerostate.seq_no() != 0
            || pin.zerostate.root_hash().is_zero()
            || pin.zerostate.file_hash().is_zero()
        {
            fail!("Session pin requires a masterchain zerostate");
        }
        let protocol =
            SimplexProtocol::try_from(u32::from(config.selected.config.protocol_version))?;
        let carrier = &config.consensus;
        let carrier_version = u32::from(carrier.proto_version);
        let max_candidate_size = u32::try_from(
            u64::from(carrier.max_block_bytes)
                + u64::from(carrier.max_collated_bytes)
                + (1u64 << 20),
        )?;
        // Charge the in-place canonicalization; no extra committee allocation.
        cb::steps(budget, committee.len())?;
        Self::normalize_committee_prefixes(&mut committee)?;
        let identity = rtos_api::session_identity::derive_session_from_decoded_bounded(
            pin.global_id,
            config,
            coordinates,
            &committee,
            budget,
        )?;
        let mut ordered = cb::vector(budget, committee.len())?;
        for v in &committee {
            ordered.push(v.adnl_addr_bounded(budget)?);
        }
        if ordered.is_empty() {
            fail!("Simplex membership has no validators");
        }
        let mut current_total_set = cb::vector(budget, config.current.list().len())?;
        for v in config.current.list() {
            current_total_set.push(v.adnl_addr_bounded(budget)?);
        }
        let extra = if protocol == SimplexProtocol::PrivateObserversPlumtree {
            config
                .previous
                .list()
                .len()
                .checked_add(config.current.list().len())
                .and_then(|n| n.checked_add(config.next.list().len()))
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| error!("Membership size overflow"))?
        } else {
            0
        };
        let mut members = cb::vector::<PublicKeyHash>(
            budget,
            ordered.len().checked_add(extra).ok_or_else(|| error!("Membership size overflow"))?,
        )?;
        fn insert(
            members: &mut Vec<PublicKeyHash>,
            key: PublicKeyHash,
            budget: &dyn cb::ConfigReadBudget,
        ) -> Result<()> {
            let mut index = 0;
            while index < members.len() {
                budget.step()?;
                match members[index].cmp(&key) {
                    std::cmp::Ordering::Equal => return Ok(()),
                    std::cmp::Ordering::Greater => break,
                    _ => index += 1,
                }
            }
            cb::steps(budget, members.len() - index)?;
            members.insert(index, key);
            Ok(())
        }
        let mut local_role = None;
        for (index, key) in ordered.iter().enumerate() {
            for previous in &ordered[..index] {
                budget.step()?;
                if key == previous {
                    fail!("Duplicate Simplex validator transport identity");
                }
            }
            if key == &local_adnl {
                local_role = Some(OverlayMemberRole::Validator(u32::try_from(index)?));
            }
            insert(&mut members, key.clone(), budget)?;
        }
        if protocol == SimplexProtocol::PrivateObserversPlumtree {
            for set in [&config.previous, &config.current, &config.next] {
                for v in set.list() {
                    insert(&mut members, v.adnl_addr_bounded(budget)?, budget)?;
                }
            }
            insert(&mut members, local_adnl.clone(), budget)?;
            if local_role.is_none() {
                local_role = Some(OverlayMemberRole::Observer);
            }
        }
        let local_role =
            local_role.ok_or_else(|| error!("ADNL identity is not a Simplex overlay member"))?;
        let pq_context =
            if committee.iter().any(|v| matches!(v.key, rtos_block::ValidatorKey::Pq(_))) {
                let mut copy = cb::vector(budget, committee.len())?;
                for v in &committee {
                    copy.push(v.clone_bounded(budget)?);
                }
                Some(PqSessionContext::from_authenticated_session_members_bounded(
                    identity.session_id.clone(),
                    coordinates.shard.clone(),
                    coordinates.catchain_seqno,
                    copy,
                    budget,
                )?)
            } else {
                None
            };
        Ok(Self {
            pin,
            coordinates: SessionRecoveryCoordinates {
                shard: coordinates.shard.clone(),
                catchain_seqno: coordinates.catchain_seqno,
                vertical_seqno: coordinates.vertical_seqno,
                last_key_block_seqno: coordinates.last_key_block_seqno,
                new_catchain_ids: coordinates.new_catchain_ids,
            },
            recovery_binding: None,
            profile: identity.config_hash,
            session: identity.session_id,
            shard: coordinates.shard.clone(),
            catchain_seqno: coordinates.catchain_seqno,
            protocol,
            carrier_version,
            slots_per_leader_window: config.selected.config.slots_per_leader_window,
            max_candidate_size,
            wire_profile: WireProfile::T0,
            committee,
            members,
            current_total_set,
            local_role,
            local_adnl,
            pq_context,
        })
    }
}
