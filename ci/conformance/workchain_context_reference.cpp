// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "block/workchain-execution-dispatch.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include <fstream>
#include <iostream>
#include <stdexcept>
static void require(bool value, const char *message) {
  if (!value)
    throw std::runtime_error(message);
}
static std::string bytes(const char *path) {
  std::ifstream f(path, std::ios::binary);
  require(bool(f), "open");
  f.seekg(0, std::ios::end);
  auto n = f.tellg();
  require(n >= 0 && n <= (4 << 20), "size");
  f.seekg(0);
  std::string s(static_cast<size_t>(n), char{});
  require(bool(f.read(s.data(), n)), "read");
  require(f.peek() == std::char_traits<char>::eof(), "grew");
  return s;
}
int main(int argc, char **argv) {
  try {
    require(argc == 5, "usage: old-wc mc1 mc1-state migrated-wc");
    auto old_bytes = bytes(argv[1]), mc_bytes = bytes(argv[2]),
         state_bytes = bytes(argv[3]), new_bytes = bytes(argv[4]);
    auto decode = [](const std::string &data) {
      auto result = vm::std_boc_deserialize(data);
      require(result.is_ok(), "invalid BOC");
      return result.move_as_ok();
    };
    auto old = decode(old_bytes), mc = decode(mc_bytes),
         state = decode(state_bytes), observed = decode(new_bytes);
    block::gen::Block::Record block, master;
    block::gen::BlockInfo::Record info, mc_info;
    block::gen::ExtBlkRef::Record previous, reference{};
    require(tlb::unpack_cell(old, block) &&
                tlb::unpack_cell(block.info, info) &&
                tlb::unpack_cell(info.master_ref, previous),
            "old block");
    require(tlb::unpack_cell(mc, master) &&
                tlb::unpack_cell(master.info, mc_info) && !mc_info.not_master &&
                mc_info.seq_no == 1,
            "master block");
    reference.end_lt = mc_info.end_lt;
    reference.seq_no = mc_info.seq_no;
    reference.root_hash = td::Bits256{mc->get_hash().bits()};
    td::sha256(mc_bytes, reference.file_hash.as_slice());
    require(previous.seq_no == reference.seq_no, "sequence");
    require(tlb::pack_cell(info.master_ref, reference) &&
                tlb::pack_cell(block.info, info),
            "pack info");
    td::Ref<vm::Cell> migrated;
    require(tlb::pack_cell(migrated, block), "pack block");
    require(migrated->get_hash() == observed->get_hash(),
            "native migrated block differs");
    for (unsigned i = 1;
         i < old->load_cell().move_as_ok().data_cell->size_refs(); ++i)
      require(old->load_cell().move_as_ok().data_cell->get_ref(i)->get_hash() ==
                  migrated->load_cell()
                      .move_as_ok()
                      .data_cell->get_ref(i)
                      ->get_hash(),
              "body changed");
    auto update = vm::load_cell_slice_special(master.state_update);
    require(update.size_refs() == 2 &&
                update.prefetch_ref(1)->get_hash(0) == state->get_hash(0),
            "state differs");
    tos::BlockIdExt id{tos::masterchainId, tos::shardIdAll, reference.seq_no,
                       reference.root_hash, reference.file_hash};
    auto extracted = block::ConfigInfo::extract_config(
        state, id,
        block::Config::needWorkchainInfo | block::Config::needCapabilities);
    require(extracted.is_ok(), "invalid config");
    auto config = extracted.move_as_ok();
    block::LocalWorkchainRoleSet local;
    local.required_workchains.insert(0);
    auto &registry = block::default_workchain_execution_registry();
    auto status = registry.validate_required_workchains(
        config->get_workchain_list(), *config, local);
    require(status.is_error(), "negative local role admitted");
    auto normalized = block::normalize_workchain_descriptor(
        *config->get_workchain_list().at(0));
    require(normalized.is_ok(), "invalid descriptor");
    auto descriptor = normalized.move_as_ok();
    descriptor.vm_version = -1;
    descriptor.vm_mode = 0;
    auto positive = registry.resolve(descriptor, *config);
    require(positive.is_ok(), "TVM control refused");
    std::cout
        << "{\"original_root\":\"" << old->get_hash().to_hex()
        << "\",\"native_migrated_root\":\"" << migrated->get_hash().to_hex()
        << "\",\"master_root\":\"" << mc->get_hash().to_hex()
        << "\",\"state_root\":\"" << state->get_hash().to_hex()
        << "\",\"local_admitted\":false,\"tvm_control\":true,\"error_hex\":\""
        << td::hex_encode(status.message()) << "\"}\n";
    return 0;
  } catch (...) {
    std::cerr << "native context verification failed\n";
    return 2;
  }
}
