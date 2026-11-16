#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include <functional>
#include <iostream>
#include <set>
#include <vector>
// Budget walk copied from TOS 5af405d validator/impl/collator.cpp:3075-3122;
// TON 857b8a57 has the same preorder decision. Uses native
// vm::ProofStorageStat. All fixture cells belong to the original storage
// dictionary, so the lookup predicate is always true. This is a focused oracle,
// not full block collation.
static bool choose(vm::ProofStorageStat &stat,
                   const std::vector<td::Ref<vm::Cell>> &roots,
                   long long budget, long long &diff) {
  std::set<vm::CellHash> seen;
  diff = 0;
  std::function<bool(td::Ref<vm::Cell>)> dfs = [&](auto cell) {
    if (!seen.insert(cell->get_hash()).second)
      return true;
    auto loaded = cell->load_cell().move_as_ok();
    switch (stat.get_cell_status(cell->get_hash())) {
    case vm::ProofStorageStat::c_none:
      diff += vm::ProofStorageStat::estimate_serialized_size(loaded.data_cell);
      break;
    case vm::ProofStorageStat::c_prunned:
      diff -= vm::ProofStorageStat::estimate_prunned_size();
      diff += vm::ProofStorageStat::estimate_serialized_size(loaded.data_cell);
      break;
    case vm::ProofStorageStat::c_loaded:
      break;
    }
    if (diff > budget)
      return false;
    vm::CellSlice cs{loaded.data_cell};
    for (unsigned i = 0; i < cs.size_refs(); ++i)
      if (!dfs(cs.prefetch_ref(i)))
        return false;
    return true;
  };
  for (const auto &root : roots)
    if (!dfs(root))
      return false;
  return true;
}
int main() {
  vm::CellBuilder b;
  for (int i = 0; i < 20; ++i)
    b.store_long(0x12345678, 32);
  auto leaf = b.finalize();
  auto small = vm::CellBuilder{}.store_long(1, 1).store_ref(leaf).finalize();
  auto owner = vm::CellBuilder{}.store_ref(small).finalize();
  for (int budget : {52, 53, 60, 85}) {
    vm::ProofStorageStat stat;
    stat.add_loaded_cell(owner->load_cell().move_as_ok().data_cell);
    long long delta;
    auto accepted = choose(stat, {small}, budget, delta);
    std::cout << "SMALL_PARENT " << budget << " " << accepted << " " << delta
              << "\n";
    if (accepted != (budget >= 53) || delta != 53)
      return 1;
  }
  auto tiny = vm::CellBuilder{}.store_long(1, 1).finalize();
  vm::CellBuilder p;
  for (int i = 0; i < 20; ++i)
    p.store_long(0x87654321, 32);
  p.store_ref(tiny);
  auto big = p.finalize();
  auto other = vm::CellBuilder{}.store_ref(tiny).finalize();
  for (int budget : {53, 60, 88}) {
    vm::ProofStorageStat stat;
    stat.add_loaded_cell(other->load_cell().move_as_ok().data_cell);
    long long delta;
    auto accepted = choose(stat, {big}, budget, delta);
    std::cout << "BIG_PARENT " << budget << " " << accepted << " " << delta
              << "\n";
    if (accepted != (budget >= 88) || delta != (accepted ? 53 : 88))
      return 2;
  }
  for (int budget : {138, 172, 173}) {
    vm::ProofStorageStat stat;
    stat.add_loaded_cell(other->load_cell().move_as_ok().data_cell);
    long long delta;
    auto accepted = choose(stat, {leaf, big}, budget, delta);
    std::cout << "MULTIPLE_ROOTS " << budget << " " << accepted << " " << delta
              << "\n";
    if (accepted != (budget >= 173) || delta != (accepted ? 138 : 173))
      return 3;
  }
  vm::ProofStorageStat dictionary_proof, selected;
  dictionary_proof.add_loaded_cell(owner->load_cell().move_as_ok().data_cell);
  long long delta;
  if (choose(selected, {leaf}, 44, delta) || delta != 85)
    return 4;
  std::cout << "BEFORE_MERGE 44 0 " << delta << "\n";
  selected.add_loaded_cells(dictionary_proof);
  if (selected.get_cell_status(owner->get_hash()) !=
          vm::ProofStorageStat::c_loaded ||
      selected.get_cell_status(small->get_hash()) !=
          vm::ProofStorageStat::c_prunned)
    return 5;
  // This proof has a boundary at small, so leaf remains absent. Use a separate
  // one-ref owner to put the boundary directly at leaf, matching the Rust test.
  auto direct_owner = vm::CellBuilder{}.store_ref(leaf).finalize();
  dictionary_proof = vm::ProofStorageStat{};
  dictionary_proof.add_loaded_cell(
      direct_owner->load_cell().move_as_ok().data_cell);
  selected = vm::ProofStorageStat{};
  selected.add_loaded_cells(dictionary_proof);
  for (int budget : {43, 44}) {
    auto accepted = choose(selected, {leaf}, budget, delta);
    std::cout << "AFTER_MERGE " << budget << " " << accepted << " " << delta
              << "\n";
    if (accepted != (budget == 44) || delta != 44)
      return 6;
  }
  selected.add_loaded_cell(leaf->load_cell().move_as_ok().data_cell);
  selected.add_loaded_cells(dictionary_proof);
  if (selected.get_cell_status(leaf->get_hash()) !=
          vm::ProofStorageStat::c_loaded ||
      !choose(selected, {direct_owner}, 0, delta) || delta != 0)
    return 7;
  std::cout << "MERGE_NO_DOWNGRADE 0 1 " << delta << "\n";
}
