// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Offline conversion of known public TON fixture cells to the pinned TOS
// schema.
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/MerkleProof.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
static std::string hex(td::Slice s) {
  const char *d = "0123456789abcdef";
  std::string out;
  for (unsigned char c : s.str()) {
    out += d[c >> 4];
    out += d[c & 15];
  }
  return out;
}
int main(int argc, char **argv) {
  if (argc < 2)
    return 2;
  for (int i = 1; i < argc; ++i) {
    std::ifstream in(argv[i], std::ios::binary);
    if (!in)
      return 2;
    in.seekg(0, std::ios::end);
    auto n = in.tellg();
    if (n < 0 || n > (64 << 20))
      return 3;
    in.seekg(0);
    std::string data(static_cast<std::size_t>(n), '\0');
    if (!in.read(data.data(), n))
      return 4;
    if (in.peek() != std::char_traits<char>::eof())
      return 3;
    auto cell = vm::std_boc_deserialize(data);
    if (cell.is_error())
      return 4;
    auto virtualized = vm::MerkleProof::virtualize(cell.ok());
    if (virtualized.is_error())
      return 5;
    auto config = block::Config::extract_from_state(virtualized.ok(), 0);
    if (config.is_error())
      return 6;
    if (config.ok()->get_size_limits_config().is_ok())
      return 15;
    auto old = config.ok()->get_config_param(43);
    if (old.is_null())
      return 7;
    auto cs = vm::load_cell_slice(old);
    if (cs.size_refs() || cs.prefetch_ulong(8) != 2 ||
        (cs.size() != 369 && cs.size() != 401))
      return 8;
    block::gen::SizeLimitsConfig::Record_size_limits_config_v2 core;
    if (!tlb::csr_unpack(cs.prefetch_subslice(368), core))
      return 9;
    auto tail = cs;
    tail.advance(368);
    bool has_limit = tail.fetch_ulong(1);
    unsigned limit = has_limit ? tail.fetch_ulong(32) : 0;
    if (tail.size())
      return 10;
    block::SizeLimitsConfig defaults;
    vm::CellBuilder builder;
    cs.advance(8);
    if (!(builder.store_long_bool(3, 8) && builder.append_cellslice_bool(cs) &&
          builder.store_long_bool(defaults.max_total_msg_bits, 32) &&
          builder.store_long_bool(defaults.max_total_msg_cells, 32) &&
          builder.store_long_bool(defaults.out_msg_queue_size_hard_limit, 32) &&
          builder.store_long_bool(defaults.out_msg_queue_size_soft_limit, 32)))
      return 11;
    auto replacement = builder.finalize();
    auto check = block::Config::do_get_size_limits_config(
        vm::load_cell_slice_ref(replacement));
    if (check.is_error())
      return 12;
    if (bool(check.ok().max_transaction_library_loads) != has_limit ||
        (has_limit &&
         check.ok().max_transaction_library_loads.value() != limit))
      return 13;
    auto before = vm::std_boc_serialize(old),
         after = vm::std_boc_serialize(replacement);
    if (before.is_error() || after.is_error())
      return 14;
    std::cout << "MIGRATION " << old->get_hash().to_hex() << " "
              << replacement->get_hash().to_hex() << " "
              << hex(before.ok().as_slice()) << " "
              << hex(after.ok().as_slice()) << " "
              << (has_limit ? std::to_string(limit) : "none") << " "
              << defaults.max_total_msg_bits << " "
              << defaults.max_total_msg_cells << " "
              << defaults.out_msg_queue_size_hard_limit << " "
              << defaults.out_msg_queue_size_soft_limit << "\n";
  }
}
