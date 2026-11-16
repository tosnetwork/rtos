// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include <iostream>
int main() {
  unsigned count, timeout, bytes, limit;
  CHECK(bool(std::cin >> count >> timeout >> bytes >> limit));
  CHECK(count == 4097 && timeout == 10 && bytes == 64 && limit == 1024);
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();
  Harness h;
  // Match the Rust fixture: one RLDP instance per endpoint, sharing only ADNL.
  td::actor::ActorOwn<tos::rldp2::Rldp> server;
  h.run([&] {
    auto key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
    auto public_key = key.compute_public_key();
    h.answerer_ = tos::adnl::AdnlNodeIdShort{public_key.compute_short_id()};
    auto address =
        tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();
    td::actor::send_closure(h.keyring_, &tos::keyring::Keyring::add_key,
                            std::move(key), true, [](td::Result<>) {});
    td::actor::send_closure(h.adnl_, &tos::adnl::Adnl::add_id,
                            tos::adnl::AdnlNodeIdFull{public_key}, address,
                            td::uint8(0));
    td::actor::send_closure(h.adnl_, &tos::adnl::Adnl::add_peer, h.requester_,
                            tos::adnl::AdnlNodeIdFull{public_key}, address);
    td::actor::send_closure(h.net_,
                            &tos::adnl::TestLoopbackNetworkManager::add_node_id,
                            h.answerer_, true, true);
    server = tos::rldp2::Rldp::create(h.adnl_.get());
    td::actor::send_closure(server, &tos::rldp2::Rldp::add_id, h.answerer_);
  });
  h.run_for(0.1);
  td::Bits256 overlay;
  overlay.set_zero();
  auto query = tos::serialize_tl_object(
      tos::create_tl_object<tos::tos_api::overlay_query>(overlay), true);
  auto held = std::make_shared<Held>();
  h.subscribe(h.answerer_, query.as_slice().truncate(4).str(),
              std::make_unique<AnnotatingSubscriber>(held));
  auto answer = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
  h.query(h.answerer_, query.clone(), timeout, limit, answer);
  h.wait_for([&] { return held->count() == 1; },
             "control query did not reach server");
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
  h.wait_for([&] { return answer->has_value(); },
             "evicted query did not complete");
  require((*answer)->is_error() && (*answer)->error().message().str().find(
                                       "evicted") != std::string::npos,
          "query did not report connection eviction");
  h.run([&] {
    held->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  auto recovered =
      std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
  h.query(h.answerer_, query.clone(), timeout, limit, recovered);
  h.wait_for([&] { return held->count() == 1; },
             "fresh query did not reach server");
  h.run([&] {
    held->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for([&] { return recovered->has_value(); },
             "fresh query did not recover");
  require((*recovered)->is_ok() &&
              (*recovered)->ok().as_slice() == std::string(bytes, '*'),
          "recovered answer differs");
  std::cout << "{\"live\":" << stats->live << ",\"evicted\":" << stats->evicted
            << ",\"evicted_query\":true,\"answer_bytes\":64}\n";
}
