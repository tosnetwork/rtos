// Replay captured proof-selection inputs using pinned native TOS primitives.
// The frozen usage snapshot comes from Rust; this is not native block
// collation.
#include "block/account-storage-stat.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/MerkleProof.h"
#include "vm/dict.h"
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>

static void require(bool ok, const char *message) {
  if (!ok)
    throw std::runtime_error(message);
}
static std::string read(const char *path, std::size_t limit) {
  std::ifstream f(path, std::ios::binary);
  require(bool(f), "cannot open input");
  f.seekg(0, std::ios::end);
  auto length = f.tellg();
  require(length >= 0 && static_cast<std::size_t>(length) <= limit,
          "input size limit");
  f.seekg(0);
  std::string data(static_cast<std::size_t>(length), '\0');
  require(bool(f.read(data.data(), length)), "short input");
  require(f.peek() == std::char_traits<char>::eof(),
          "input grew while reading");
  return data;
}
static td::Bits256 hash(const std::string &text) {
  require(text.size() == 64, "hash length");
  auto bytes = td::hex_decode(text);
  require(bytes.is_ok() && bytes.ok().size() == 32, "hash encoding");
  td::Bits256 value;
  std::memcpy(value.data(), bytes.ok().data(), 32);
  return value;
}
struct Frozen {
  int status;
  bool included;
  td::Ref<vm::Cell> cell;
};
static int run(int argc, char **argv) {
  require(argc == 5,
          "usage: probe snapshot roots-boc dictionary-proof-boc state-boc");
  auto snapshot_text = read(argv[1], 16 << 20);
  std::istringstream snapshot(snapshot_text);
  std::string line, kind, dictionary_hash, account_hash, state_hash;
  long long budget = -1;
  int expected_fit = -1;
  require(bool(std::getline(snapshot, line)) && line.size() < 1024,
          "missing header");
  std::istringstream header(line);
  header >> kind >> budget >> expected_fit >> dictionary_hash >> account_hash >>
      state_hash;
  require(bool(header) && kind == "CASE" && budget >= 0 && expected_fit >= 0 &&
              expected_fit <= 1,
          "invalid header");
  std::map<std::string, Frozen> frozen;
  while (std::getline(snapshot, line)) {
    require(line.size() < 1024, "snapshot line limit");
    std::istringstream row(line);
    std::string h;
    int status = -1, included = -1;
    row >> kind >> h >> status >> included;
    require(bool(row) && kind == "STATUS" && status >= 0 && status <= 2 &&
                included >= 0 && included <= 1,
            "invalid status");
    h = hash(h).to_hex();
    require(frozen.emplace(h, Frozen{status, included != 0, {}}).second,
            "duplicate snapshot cell");
    require(frozen.size() <= 100000, "snapshot cell limit");
  }
  require(!frozen.empty(), "empty snapshot");
  auto state =
      vm::MerkleProof::virtualize(
          vm::std_boc_deserialize(read(argv[4], 64 << 20)).move_as_ok())
          .move_as_ok();
  require(state->get_hash().to_hex() == hash(state_hash).to_hex(),
          "state root differs");
  block::gen::ShardStateUnsplit::Record shard_state;
  require(tlb::unpack_cell(state, shard_state), "cannot unpack state");
  vm::AugmentedDictionary accounts{
      vm::load_cell_slice_ref(shard_state.accounts), 256,
      block::tlb::aug_ShardAccounts};
  auto account_id = hash(account_hash);
  auto value = accounts.lookup(account_id.bits(), 256);
  block::gen::ShardAccount::Record shard_account;
  block::gen::Account::Record_account account;
  block::gen::AccountStorage::Record storage;
  block::gen::StateInit::Record init;
  require(value.not_null() && tlb::csr_unpack(value, shard_account) &&
              tlb::unpack_cell(shard_account.account, account) &&
              tlb::csr_unpack(account.storage, storage) &&
              storage.state->prefetch_ulong(1) == 1,
          "cannot unpack active account");
  storage.state.write().advance(1);
  require(tlb::csr_unpack(storage.state, init), "cannot unpack state init");
  std::vector<td::Ref<vm::Cell>> storage_roots;
  for (auto field : {init.code, init.data, init.library})
    if (field->prefetch_ulong(1))
      storage_roots.push_back(field->prefetch_ref());
  block::AccountStorageStat full;
  full.replace_roots(storage_roots).ensure();
  auto dictionary_root = full.get_dict_root().move_as_ok();
  require(dictionary_root->get_hash().to_hex() ==
              hash(dictionary_hash).to_hex(),
          "native dictionary root differs");
  vm::Dictionary dictionary{dictionary_root, 256};
  auto proof_cell =
      vm::std_boc_deserialize(read(argv[3], 4 << 20)).move_as_ok();
  auto proof_root = vm::MerkleProof::virtualize(proof_cell).move_as_ok();
  require(proof_root->get_hash() == dictionary_root->get_hash(),
          "dictionary proof root differs");
  std::set<vm::CellHash> proof_seen;
  std::function<long long(td::Ref<vm::Cell>)> proof_size = [&](auto cell) {
    if (!proof_seen.insert(cell->get_hash(0)).second)
      return 0LL;
    auto loaded = cell->load_cell().move_as_ok();
    if (loaded.data_cell->special_type() ==
        vm::CellTraits::SpecialType::PrunnedBranch)
      return static_cast<long long>(
          vm::ProofStorageStat::estimate_prunned_size());
    long long size =
        vm::ProofStorageStat::estimate_serialized_size(loaded.data_cell);
    for (unsigned i = 0; i < loaded.data_cell->size_refs(); ++i)
      size += proof_size(loaded.data_cell->get_ref(i));
    return size;
  };
  require(proof_size(proof_cell->load_cell().move_as_ok().data_cell->get_ref(
              0)) == budget,
          "native proof budget differs");
  auto serialized_roots =
      vm::std_boc_deserialize_multi(read(argv[2], 4 << 20)).move_as_ok();
  require(!serialized_roots.empty() && serialized_roots.size() <= 128,
          "root count limit");
  std::vector<td::Ref<vm::Cell>> roots;
  for (auto proof : serialized_roots)
    roots.push_back(vm::MerkleProof::virtualize(proof).move_as_ok());
  std::set<std::string> indexed;
  std::function<void(td::Ref<vm::Cell>)> index = [&](auto cell) {
    auto h = cell->get_hash().to_hex();
    auto it = frozen.find(h);
    if (it == frozen.end() || !indexed.insert(h).second)
      return;
    it->second.cell = cell;
    vm::CellSlice cs{vm::NoVm(), cell};
    for (unsigned i = 0; i < cs.size_refs(); ++i)
      index(cs.prefetch_ref(i));
  };
  for (auto root : roots)
    index(root);
  require(indexed.size() == frozen.size(), "snapshot cells not reachable");
  vm::ProofStorageStat stat;
  for (auto &[h, item] : frozen)
    if (item.status == 1) {
      auto owner = vm::CellBuilder{}
                       .store_long(0x4e415456, 32)
                       .store_ref(item.cell)
                       .finalize();
      require(!frozen.count(owner->get_hash().to_hex()), "seed owner collides");
      auto loaded = owner->load_cell().move_as_ok();
      stat.add_loaded_cell(loaded.data_cell, loaded.effective_level);
    }
  for (auto &[h, item] : frozen)
    if (item.status == 2) {
      auto loaded = item.cell->load_cell().move_as_ok();
      stat.add_loaded_cell(loaded.data_cell, loaded.effective_level);
    }
  for (auto &[h, item] : frozen) {
    require(stat.get_cell_status(item.cell->get_hash()) == item.status,
            "native seeded status differs");
    require(dictionary.lookup(item.cell->get_hash().bits(), 256).not_null() ==
                item.included,
            "native dictionary membership differs");
  }
  // TOS5af collator.cpp:3075-3122. Charge immediately, before children, against
  // one budget across all roots. Read the actual native dictionary and
  // statistic.
  std::set<vm::CellHash> seen;
  long long delta = 0;
  std::function<bool(td::Ref<vm::Cell>)> dfs = [&](auto cell) {
    if (!seen.insert(cell->get_hash()).second)
      return true;
    require(frozen.count(cell->get_hash().to_hex()),
            "walk passed captured prefix");
    auto loaded = cell->load_cell().move_as_ok();
    if (dictionary.lookup(cell->get_hash().bits(), 256).not_null()) {
      auto status = stat.get_cell_status(cell->get_hash());
      if (status != vm::ProofStorageStat::c_loaded)
        delta +=
            vm::ProofStorageStat::estimate_serialized_size(loaded.data_cell);
      if (status == vm::ProofStorageStat::c_prunned)
        delta -= vm::ProofStorageStat::estimate_prunned_size();
      if (delta > budget)
        return false;
    }
    vm::CellSlice cs{vm::NoVm(), cell};
    for (unsigned i = 0; i < cs.size_refs(); ++i)
      if (!dfs(cs.prefetch_ref(i)))
        return false;
    return true;
  };
  bool fits = true;
  for (auto root : roots)
    if (!dfs(root)) {
      fits = false;
      break;
    }
  require(seen.size() == frozen.size(),
          "captured prefix contains unvisited cells");
  require(fits == bool(expected_fit), "native selection differs");
  std::cout << "{\"fits\":" << (fits ? "true" : "false")
            << ",\"stopping_delta\":" << delta
            << ",\"visited_cells\":" << seen.size() << "}\n";
  return 0;
}
int main(int argc, char **argv) {
  try {
    return run(argc, argv);
  } catch (...) {
    std::cerr << "native proof-selection input or replay failed\n";
    return 2;
  }
}
