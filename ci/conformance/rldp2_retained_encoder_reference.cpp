// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include <iostream>

int main() {
  unsigned silent_count, silent_timeout, healthy_timeout, bytes, limit;
  CHECK(bool(std::cin >> silent_count >> silent_timeout >> healthy_timeout >>
             bytes >> limit));
  CHECK(silent_count == 16 && silent_timeout == 60 && healthy_timeout == 10 &&
        bytes == 262144 && limit == 524288);
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();
  Harness h;
  // The borrowed fixture only registers requester-to-server address routes.
  // Register the independent healthy identity explicitly before the probe.
  std::optional<tos::PublicKey> server_key;
  h.run([&] {
    td::actor::send_closure(h.keyring_, &tos::keyring::Keyring::get_public_key,
                            h.answerer_.pubkey_hash(),
                            [&](td::Result<tos::PublicKey> result) {
                              server_key = result.move_as_ok();
                            });
  });
  h.wait_for([&] { return server_key.has_value(); }, "server key unavailable");
  h.run([&] {
    td::actor::send_closure(
        h.adnl_, &tos::adnl::Adnl::add_peer, h.buffered_,
        tos::adnl::AdnlNodeIdFull{*server_key},
        tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list());
  });
  auto held = std::make_shared<Held>();
  td::Bits256 overlay;
  overlay.set_zero();
  auto request = tos::serialize_tl_object(
      tos::create_tl_object<tos::tos_api::overlay_query>(overlay), true);
  h.subscribe(h.answerer_, request.as_slice().truncate(4).str(),
              std::make_unique<AnnotatingSubscriber>(held));
  h.requester_receives(false);
  for (unsigned i = 0; i < silent_count; ++i) {
    auto result =
        std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
    h.query(h.answerer_, request.clone(), silent_timeout, limit, result);
  }
  h.wait_for([&] { return held->count() == silent_count; },
             "silent queries did not reach subscriber");
  h.run([&] {
    held->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for([&] { return h.outbound(h.answerer_).live == silent_count; },
             "silent response transfers did not start");
  auto healthy = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
  h.run([&] {
    td::actor::send_closure(
        h.rldp_, &tos::rldp2::Rldp::send_query_ex, h.buffered_, h.answerer_,
        std::string("healthy"),
        [healthy](td::Result<td::BufferSlice> result) {
          *healthy = std::move(result);
        },
        td::Timestamp::in(healthy_timeout), request.clone(), limit);
  });
  h.wait_for([&] { return held->count() == 1; },
             "healthy query did not reach subscriber");
  h.run([&] {
    held->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for([&] { return healthy->has_value(); }, "healthy query starved");
  require((*healthy)->is_ok() &&
              (*healthy)->ok().as_slice() == std::string(bytes, '*'),
          "healthy response failed");
  h.wait_for([&] { return h.outbound(h.answerer_).live == silent_count; },
             "silent response retention changed");
  std::printf("{\"silent_live\":16,\"healthy_answer_bytes\":262144,\"healthy_"
              "completed\":true}\n");
}
