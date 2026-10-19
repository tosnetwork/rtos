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
use super::*;
use rtos_block::{BuilderData, ConfigParam0, ConfigParam15, IBitstring, MsgAddressInt, StateInit};

/// A configuration the reference accepts (`workchain-base-original-r0` in the
/// block crate's configuration corpus).
fn base_config() -> ConfigParams {
    let bytes = include_bytes!("../../../../block/src/tests/data/workchain-config-base.boc");
    ConfigParams::with_root(rtos_block::read_single_root_boc(bytes).unwrap()).unwrap()
}

fn with_address(config: &ConfigParams, address: [u8; 32]) -> ConfigParams {
    let mut config = config.clone();
    config
        .set_config(ConfigParamEnum::ConfigParam0(ConfigParam0 {
            config_addr: AccountId::from(address),
        }))
        .unwrap();
    config.config_addr = AccountId::from(address);
    config
}

fn changed(config: &ConfigParams) -> ConfigParams {
    let mut config = config.clone();
    config
        .set_config(ConfigParamEnum::ConfigParam15(ConfigParam15 {
            validators_elected_for: 77,
            elections_start_before: 7,
            elections_end_before: 7,
            stake_held_for: 7,
        }))
        .unwrap();
    config
}

/// The persistent data of a configuration contract: the dictionary root in
/// the first reference, as the reference contract stores it.
fn wrapper(root: &Cell) -> Cell {
    let mut data = BuilderData::new();
    data.append_u32(0).unwrap();
    data.checked_append_reference(root.clone()).unwrap();
    data.into_cell().unwrap()
}

fn add_contract(accounts: &mut ShardAccounts, address: [u8; 32], data: Cell) {
    let state = StateInit::with_code_and_data(Cell::default(), data);
    let account = Account::active(
        MsgAddressInt::standard(-1, AccountId::from(address)),
        CurrencyCollection::with_coins(1_000_000_000),
        1,
        1,
        state,
        0,
    )
    .unwrap();
    accounts.insert(0, &account, UInt256::default(), 1).unwrap();
}

struct Scenario {
    prev: ConfigParams,
    next: ConfigParams,
    accounts: ShardAccounts,
}

impl Scenario {
    fn run(&self) -> Result<()> {
        let mut base = ValidateBase {
            config_params: self.prev.clone(),
            next_state_accounts: self.accounts.clone(),
            ..Default::default()
        };
        // A configuration change must come in a key block.
        base.info.set_key_block(self.prev.root() != self.next.root());
        base.prev_state_extra.config = self.prev.clone();
        base.next_state_extra.config = self.next.clone();
        ValidateQuery::check_config_update(&base)
    }
}

const A: [u8; 32] = [0xa1; 32];
const B: [u8; 32] = [0xb2; 32];
const C: [u8; 32] = [0xc3; 32];

fn unchanged() -> Scenario {
    let config = with_address(&base_config(), A);
    let mut accounts = ShardAccounts::default();
    add_contract(&mut accounts, A, wrapper(config.root().unwrap()));
    Scenario { prev: config.clone(), next: config, accounts }
}

fn is_rejection(result: &Result<()>) -> bool {
    matches!(
        result.as_ref().err().and_then(|e| e.downcast_ref::<NodeError>()),
        Some(NodeError::ValidatorReject(_))
    )
}

fn rejected_with(result: Result<()>, text: &str) {
    assert!(is_rejection(&result), "{result:?}");
    let message = result.unwrap_err().to_string();
    assert!(message.contains(text), "{message}");
}

#[test]
fn config_update_accepts_matching_contract_data() {
    assert!(base_config().config_data_is_valid(false, None));
    unchanged().run().unwrap();
}

// Unchanged address: the next state configuration must equal the dictionary
// held by the configuration contract in the next account state.
#[test]
fn config_update_rejects_contract_data_differing_from_state() {
    let mut scenario = unchanged();
    let other = changed(&scenario.next);
    let mut accounts = ShardAccounts::default();
    add_contract(&mut accounts, A, wrapper(other.root().unwrap()));
    scenario.accounts = accounts;
    rejected_with(scenario.run(), "different from that stored in the persistent data");
}

// The dictionary root is the first reference of the contract data, not the
// data cell itself.
#[test]
fn config_update_reads_the_first_reference_of_contract_data() {
    let mut scenario = unchanged();
    let mut accounts = ShardAccounts::default();
    add_contract(&mut accounts, A, scenario.next.root().unwrap().clone());
    scenario.accounts = accounts;
    rejected_with(scenario.run(), "different from that stored in the persistent data");
    let mut accounts = ShardAccounts::default();
    add_contract(&mut accounts, A, BuilderData::new().into_cell().unwrap());
    scenario.accounts = accounts;
    rejected_with(scenario.run(), "cannot extract configuration from the new state of the (old)");
}

// A changed address is looked up at the new address.
#[test]
fn config_update_looks_up_the_new_contract_at_the_new_address() {
    let prev = with_address(&base_config(), A);
    let next = with_address(&base_config(), B);
    // The old contract asks for B, the new contract holds the next configuration.
    let old_contract = with_address(&base_config(), B);
    let mut accounts = ShardAccounts::default();
    add_contract(&mut accounts, A, wrapper(old_contract.root().unwrap()));
    let scenario = Scenario { prev: prev.clone(), next: next.clone(), accounts: accounts.clone() };
    rejected_with(scenario.run(), "cannot extract configuration from the new state of the (new)");

    let mut with_new = accounts.clone();
    add_contract(&mut with_new, B, wrapper(changed(&next).root().unwrap()));
    let scenario = Scenario { prev: prev.clone(), next: next.clone(), accounts: with_new };
    rejected_with(scenario.run(), "different from that stored in the persistent data");

    // Matching data at B: the reference then evaluates the suggested switchover
    // to B, whose configuration is valid, and rejects the block.
    let mut with_new = accounts.clone();
    add_contract(&mut with_new, B, wrapper(next.root().unwrap()));
    let scenario = Scenario { prev: prev.clone(), next: next.clone(), accounts: with_new };
    rejected_with(scenario.run(), "the switchover did not happen without a good reason");

    // The old contract asking for a third address while the address changed to B.
    let mut accounts = ShardAccounts::default();
    add_contract(&mut accounts, A, wrapper(with_address(&base_config(), C).root().unwrap()));
    add_contract(&mut accounts, B, wrapper(next.root().unwrap()));
    let scenario = Scenario { prev, next, accounts };
    rejected_with(scenario.run(), "changed to a different value");
}

// The configuration held by the old contract in the next state is validated
// with relaxed parameter 0.
#[test]
fn config_update_validates_the_old_contract_configuration() {
    let prev = with_address(&base_config(), A);
    let next = with_address(&base_config(), B);
    let mut broken = with_address(&base_config(), B);
    broken.set_config(ConfigParamEnum::ConfigParamAny(26, Cell::default())).unwrap();
    let mut accounts = ShardAccounts::default();
    add_contract(&mut accounts, A, wrapper(broken.root().unwrap()));
    add_contract(&mut accounts, B, wrapper(next.root().unwrap()));
    let scenario = Scenario { prev, next, accounts };
    rejected_with(
        scenario.run(),
        "configuration extracted from (old) configuration smart contract",
    );
}

// Switchover paths. With an unchanged address the old and the new contract
// are the same, so parameter 0 of the held configuration must already name
// that contract (the strict check of the next configuration); a suggested
// switch can only be observed together with an address change, and the
// reference then rejects the block whenever the suggested contract holds a
// valid configuration (see config_update_looks_up_the_new_contract_at_the_new_address).
#[test]
fn config_update_switchover_paths() {
    let prev = with_address(&base_config(), A);
    let held = with_address(&base_config(), C);
    let mut next = held.clone();
    next.config_addr = AccountId::from(A);
    let mut accounts = ShardAccounts::default();
    add_contract(&mut accounts, A, wrapper(held.root().unwrap()));
    let scenario = Scenario { prev, next, accounts };
    rejected_with(scenario.run(), "failed to pass per-parameter automated validity");
}

// Malformed next configuration is a rejection; a malformed previous state is
// an internal failure.
#[test]
fn config_update_distinguishes_new_and_old_shape_failures() {
    let mut scenario = unchanged();
    let malformed = ConfigParams::with_address_and_params(
        AccountId::from(A),
        Some(BuilderData::new().into_cell().unwrap()),
    );
    scenario.next = malformed.clone();
    rejected_with(scenario.run(), "new configuration failed to pass automated validity checks");
    let mut scenario = unchanged();
    scenario.prev = malformed;
    let result = scenario.run();
    assert!(result.is_err() && !is_rejection(&result), "{result:?}");
}

// The previous mandatory-parameter list is enforced on the next configuration.
#[test]
fn config_update_enforces_previous_mandatory_list() {
    let mut scenario = unchanged();
    let mut prev = scenario.prev.clone();
    let mut list = rtos_block::ConfigParam9::default();
    list.mandatory_params.set(&77u32, &rtos_block::EmptyValue).unwrap();
    prev.set_config(ConfigParamEnum::ConfigParam9(list)).unwrap();
    scenario.prev = prev;
    rejected_with(scenario.run(), "one of mandatory configuration parameters is missing");
}
