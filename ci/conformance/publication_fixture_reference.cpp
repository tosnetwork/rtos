// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Public synthetic fixture identities only; this tool never reads a key file.
#include "auto/tl/tos_api.hpp"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "block/signature-set.h"
#include "block/validator-session-id.h"
#include "block/validator-set.h"
#include "common/checksum.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "td/utils/crypto.h"
#include "tl-utils/common-utils.hpp"
#include "tl-utils/tl-utils.hpp"
#include "vm/boc.h"
#include <array>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
static std::string hex(std::string_view value) {
  const char *digits = "0123456789abcdef";
  std::string out;
  for (unsigned char c : value) {
    out += digits[c >> 4];
    out += digits[c & 15];
  }
  return out;
}
// All inputs are public fixture data. Cap each hex token before allocating.
constexpr std::size_t max_token_bytes = 2 << 20;
static bool token(std::string &value) {
  if (!(std::cin >> std::setw(max_token_bytes + 1) >> value))
    return false;
  if (value.size() > max_token_bytes)
    throw std::runtime_error("fixture input token too large");
  return true;
}
static std::string unhex(const std::string &value) {
  if (value.size() % 2)
    throw std::runtime_error("odd hex");
  auto digit = [](unsigned char c) -> int {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    throw std::runtime_error("non-hex fixture input");
  };
  std::string out;
  out.reserve(value.size() / 2);
  for (std::size_t i = 0; i < value.size(); i += 2)
    out += static_cast<char>((digit(value[i]) << 4) | digit(value[i + 1]));
  return out;
}
static int run(int argc, char **argv) {
  const bool history = argc == 2 && std::string(argv[1]) == "--check-history";
  if (history || (argc == 2 && std::string(argv[1]) == "--check")) {
    std::string state_hex, block_hex, candidate_hex, governing_hex;
    unsigned slot;
    while (token(state_hex)) {
      if (!token(block_hex) || !token(candidate_hex) || !(std::cin >> slot) ||
          (history && !token(governing_hex)))
        return 3;
      auto state_raw = unhex(state_hex), block_raw = unhex(block_hex);
      auto state = vm::std_boc_deserialize(state_raw),
           root = vm::std_boc_deserialize(block_raw);
      if (state.is_error() || root.is_error())
        return 10;
      auto config = block::Config::extract_from_state(
          state.ok(), block::ConfigInfo::needValidatorSet);
      if (config.is_error()) {
        std::cerr << config.error().message().str() << "\n";
        return 11;
      }
      block::gen::Block::Record blk;
      block::gen::BlockInfo::Record info;
      block::gen::ExtBlkRef::Record master;
      tos::ShardIdFull shard;
      if (!(tlb::unpack_cell(root.ok(), blk) &&
            tlb::unpack_cell(blk.info, info) &&
            block::tlb::t_ShardIdent.unpack(info.shard.write(), shard)))
        return 12;
      if (!history) {
        if (!info.not_master || !tlb::unpack_cell(info.master_ref, master))
          return 12;
        if (master.root_hash != state.ok()->get_hash().bits() ||
            master.file_hash != td::sha256_bits256(state_raw))
          return 13;
      } else if (info.not_master) {
        if (!tlb::unpack_cell(info.master_ref, master))
          return 12;
        if (master.seq_no == 0) {
          if (master.root_hash != state.ok()->get_hash().bits() ||
              master.file_hash != td::sha256_bits256(state_raw))
            return 13;
        } else {
          auto gov_raw = unhex(governing_hex);
          auto gov = vm::std_boc_deserialize(gov_raw);
          block::gen::Block::Record gov_block;
          block::gen::BlockInfo::Record gov_info;
          if (gov.is_error() || !tlb::unpack_cell(gov.ok(), gov_block) ||
              !tlb::unpack_cell(gov_block.info, gov_info))
            return 20;
          if (gov_info.not_master || gov_info.seq_no != master.seq_no ||
              master.root_hash != gov.ok()->get_hash().bits() ||
              td::sha256_bits256(gov_raw) != master.file_hash)
            return 21;
          vm::CellSlice update{vm::NoVm(), gov_block.state_update};
          if (!update.is_special() || update.prefetch_long(8) != 4 ||
              update.size_ext() != 0x20228 ||
              td::Bits256{update.prefetch_ref(1)->get_hash(0).bits()} !=
                  td::Bits256{state.ok()->get_hash().bits()})
            return 22;
        }
      } else {
        vm::CellSlice update{vm::NoVm(), blk.state_update};
        if (!update.is_special() || update.prefetch_long(8) != 4 ||
            update.size_ext() != 0x20228 ||
            td::Bits256{update.prefetch_ref(0)->get_hash(0).bits()} !=
                td::Bits256{state.ok()->get_hash().bits()})
          return 23;
      }
      auto nodes = config.ok()->compute_validator_set(shard, info.gen_utime,
                                                      info.gen_catchain_seqno);
      if (nodes.size() != 3)
        return 14;
      td::Ref<block::ValidatorSet> validators{true, info.gen_catchain_seqno,
                                              shard, nodes};
      auto options = config.ok()->get_consensus_config();
      auto selected =
          config.ok()->get_selected_new_consensus_config(shard.workchain);
      if (!selected)
        return 15;
      auto identity = block::derive_validator_session_identity(
          config.ok()->get_global_blockchain_id(),
          block::validator_session_options_hash(options),
          selected.value().cell_hash, shard, info.gen_catchain_seqno, nodes,
          info.vert_seq_no, info.prev_key_block_seqno,
          options.new_catchain_ids);
      if (validators->get_validator_set_hash() !=
          info.gen_validator_list_hash_short)
        return 17;
      const tos::BlockIdExt block_id{
          tos::BlockId{shard, static_cast<unsigned>(info.seq_no)},
          root.ok()->get_hash().bits(), td::sha256_bits256(block_raw)};
      auto candidate =
          tos::fetch_tl_object<tos::tos_api::consensus_CandidateHashData>(
              td::BufferSlice(unhex(candidate_hex)), true);
      if (candidate.is_error())
        return 18;
      auto final_message = block::BlockSignatureSet::build_simplex_data_to_sign(
          identity.session_id, slot, candidate.ok(), true, block_id);
      auto approval_message =
          block::BlockSignatureSet::build_simplex_data_to_sign(
              identity.session_id, slot, candidate.ok(), false, block_id);
      if (final_message.is_error() || approval_message.is_error())
        return 19;
      td::Bits256 candidate_hash{tos::get_tl_object_sha256(candidate.ok()).raw};
      auto candidate_message =
          tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(
              identity.session_id,
              tos::create_serialize_tl_object<
                  tos::tos_api::consensus_candidateId>(slot, candidate_hash));
      std::cout << "CHECK " << identity.session_id.to_hex() << " "
                << validators->get_validator_set_hash() << " "
                << info.gen_validator_list_hash_short << " "
                << root.ok()->get_hash().to_hex() << " "
                << td::sha256_bits256(block_raw).to_hex() << " "
                << hex(final_message.ok().as_slice().str()) << " "
                << hex(approval_message.ok().as_slice().str()) << " "
                << hex(candidate_message.as_slice().str()) << "\n";
    }
    return std::cin.eof() ? 0 : 16;
  }
  if (argc != 1)
    return 2;
  std::array<std::optional<tos::pq::ValidatorPQKeyStore>, 3> stores;
  for (unsigned i = 0; i < 3; ++i) {
    stores[i] = tos::pq::ValidatorPQKeyStore::from_seed(
        td::sha256(std::string("rtos/publication-custody-fixture/v1/") +
                   std::to_string(i)));
    if (!stores[i])
      return 2;
    std::cout << "KEY " << i << " "
              << hex(stores[i]->consensus_key().public_key) << "\n";
  }
  for (unsigned member; std::cin >> member;) {
    std::string data;
    if (!token(data) || member >= 3 || data.size() % 2)
      return 3;
    auto message = unhex(data);
    auto signature = stores[member]->sign_consensus(message);
    if (!signature)
      return 4;
    std::cout << "SIGNATURE " << member << " " << hex(signature->signature)
              << "\n";
  }
  return std::cin.eof() ? 0 : 5;
}

int main(int argc, char **argv) {
  try {
    return run(argc, argv);
  } catch (const std::exception &error) {
    std::cerr << error.what() << "\n";
    return 3;
  }
}
