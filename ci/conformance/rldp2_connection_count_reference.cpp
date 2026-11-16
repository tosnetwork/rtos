// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include <iostream>
int main() {
  unsigned count;
  CHECK(bool(std::cin >> count) && count == 4097);
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();
  Harness h;
  h.run([&] {
    for (unsigned i = 0; i < count; ++i) {
      td::Bits256 id;
      id.set_zero();
      id.as_slice().copy_from(
          td::Slice(reinterpret_cast<const char *>(&i), sizeof(i)));
      td::actor::send_closure(h.rldp_, &tos::rldp2::Rldp::send_message,
                              h.requester_, tos::adnl::AdnlNodeIdShort{id},
                              td::BufferSlice("x"));
    }
  });
  std::optional<tos::rldp2::Rldp::ConnectionStats> stats;
  h.run([&] {
    td::actor::send_closure(
        h.rldp_, &tos::rldp2::Rldp::get_connection_stats,
        [&](td::Result<tos::rldp2::Rldp::ConnectionStats> result) {
          stats = result.move_as_ok();
        });
  });
  h.wait_for([&] { return stats.has_value(); }, "connection stats missing");
  CHECK(stats->live <= 4096 && stats->evicted > 0);
  std::cout << "{\"submitted\":" << count << ",\"live\":" << stats->live
            << ",\"evicted\":" << stats->evicted << "}\n";
}
