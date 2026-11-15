// Native TOS AccountStorageStat comparison for the Rust pruned-hint regression.
// Build/run with storage_hint_reference.py against ci/conformance/REFERENCE.
// Force unvisited leaves to standard pruned branches: the usual C++ proof
// generator keeps leaves, while these valid inputs exercise the Rust fixture.
#include "block/account-storage-stat.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/MerkleProof.h"
#include "vm/dict.h"
#include <iostream>
using td::Ref;
Ref<vm::Cell> node(unsigned tag, std::vector<Ref<vm::Cell>> refs = {}) {
  vm::CellBuilder b;
  b.store_long(tag, 32);
  for (auto c : refs)
    b.store_ref(c);
  return b.finalize();
}
Ref<vm::Cell> force_proof(Ref<vm::Cell> cell, const vm::CellUsageTree &usage,
                          unsigned id) {
  if (!usage.is_loaded(id))
    return vm::CellBuilder::do_create_pruned_branch(cell, 1, 0);
  vm::CellSlice cs(vm::NoVm(), cell);
  vm::CellBuilder b;
  b.store_bits(cs.fetch_bits(cs.size()));
  for (unsigned i = 0; i < cs.size_refs(); ++i)
    b.store_ref(force_proof(cs.prefetch_ref(i), usage, usage.get_child(id, i)));
  return b.finalize(cs.is_special());
}
bool unavailable(Ref<vm::Cell> dict, Ref<vm::Cell> key) {
  try {
    vm::Dictionary d(dict, 256);
    d.lookup(key->get_hash().bits(), 256);
    return false;
  } catch (const vm::VmVirtError &) {
    return true;
  }
}
int main() {
  auto gc = node(0xcc), shared = node(0x55, {gc}), old = node(0x0a, {shared});
  block::AccountStorageStat full;
  full.replace_roots({old}).ensure();
  auto dict = full.get_dict_root().move_as_ok();
  for (unsigned tag = 11; tag < 4096; ++tag) {
    auto next = node(tag, {shared});
    vm::MerkleProofBuilder builder(dict);
    vm::Dictionary tracked(builder.root(), 256);
    tracked.lookup(old->get_hash().bits(), 256);
    tracked.lookup(next->get_hash().bits(), 256);
    auto proof = force_proof(dict, builder.get_usage_tree(),
                             builder.get_usage_tree().root_id())
                     ->virtualize(0);
    if (!unavailable(proof, shared) || !unavailable(proof, gc))
      continue;
    auto old_proof =
        vm::MerkleProof::virtualize(
            vm::MerkleProof::generate(old,
                                      [&](const Ref<vm::Cell> &cell) {
                                        return cell->get_hash() ==
                                               shared->get_hash();
                                      })
                .move_as_ok())
            .move_as_ok();
    for (int mode = 0; mode < 4; ++mode) {
      bool accepted = false;
      try {
        block::AccountStorageStat s(mode == 3 ? dict : proof, {old_proof},
                                    full.get_total_cells(),
                                    full.get_total_bits());
        if (mode) {
          td::HashSet<vm::CellHash> loaded;
          loaded.insert(old->get_hash());
          s.add_hint(loaded);
        }
        auto result =
            s.replace_roots(mode >= 2 ? std::vector<Ref<vm::Cell>>{next, shared}
                                      : std::vector<Ref<vm::Cell>>{next});
        accepted = result.is_ok();
        if (accepted) {
          auto hash = s.get_dict_hash();
          accepted = hash.is_ok();
          if (accepted) {
            block::AccountStorageStat rebuilt;
            rebuilt
                .replace_roots(mode >= 2
                                   ? std::vector<Ref<vm::Cell>>{next, shared}
                                   : std::vector<Ref<vm::Cell>>{next})
                .ensure();
            if (rebuilt.get_dict_hash().move_as_ok() != hash.ok() ||
                rebuilt.get_total_cells() != s.get_total_cells() ||
                rebuilt.get_total_bits() != s.get_total_bits())
              return 6;
          }
          if (accepted)
            std::cout << "tag=" << tag << " mode=" << mode
                      << " cells=" << s.get_total_cells()
                      << " bits=" << s.get_total_bits()
                      << " hash=" << hash.ok().to_hex() << '\n';
        }
      } catch (const vm::VmVirtError &) {
        accepted = false;
      }
      std::cout << "mode=" << mode << " accepted=" << accepted << '\n';
      if (accepted != (mode == 1 || mode == 3))
        return 2;
    }
    vm::MerkleProofBuilder old_builder(dict);
    vm::Dictionary old_tracked(old_builder.root(), 256);
    old_tracked.lookup(old->get_hash().bits(), 256);
    auto missing = force_proof(dict, old_builder.get_usage_tree(),
                               old_builder.get_usage_tree().root_id())
                       ->virtualize(0);
    for (unsigned bad_tag = 11; bad_tag < 4096; ++bad_tag) {
      auto bad = node(bad_tag, {shared});
      if (!unavailable(missing, bad))
        continue;
      bool accepted = false;
      try {
        block::AccountStorageStat s(missing, {old_proof},
                                    full.get_total_cells(),
                                    full.get_total_bits());
        td::HashSet<vm::CellHash> loaded;
        loaded.insert(old->get_hash());
        s.add_hint(loaded);
        accepted = s.replace_roots({bad}).is_ok();
      } catch (const vm::VmVirtError &) {
        accepted = false;
      }
      std::cout << "missing_new_path_tag=" << bad_tag
                << " accepted=" << accepted << '\n';
      if (accepted)
        return 4;
      return 0;
    }
    return 5;
  }
  return 3;
}
