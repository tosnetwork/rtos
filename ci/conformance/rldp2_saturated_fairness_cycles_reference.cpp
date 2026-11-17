// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include <iostream>

int main() {
  unsigned rounds, silent_count, healthy_count, bytes, silent_timeout,
      healthy_timeout, limit;
  CHECK(bool(std::cin >> rounds >> silent_count >> healthy_count >> bytes >>
             silent_timeout >> healthy_timeout >> limit));
  CHECK(rounds == 4 && silent_count == 256 && healthy_count == 32 &&
        bytes == 64 && silent_timeout == 60 && healthy_timeout == 10 &&
        limit == 1024);
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
  // Establish the requester channel before suppressing its response traffic.
  auto warm = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
  h.query(h.answerer_, request.clone(), healthy_timeout, limit, warm);
  h.wait_for([&] { return held->count() == 1; }, "warm query absent");
  h.run([&] {
    held->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for(
      [&] {
        return warm->has_value() && h.outbound(h.answerer_).live == 0 &&
               h.outbound(h.requester_).live == 0;
      },
      "warm query not retired");
  CHECK((*warm)->is_ok());
  auto baseline = h.outbound(h.answerer_).started;
  CHECK(baseline == 1);
  for (unsigned round = 0; round < rounds; ++round) {
    h.requester_receives(false);
    std::vector<std::shared_ptr<std::optional<td::Result<td::BufferSlice>>>>
        silent;
    for (unsigned i = 0; i < silent_count; ++i) {
      auto result =
          std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
      silent.push_back(result);
      h.query(h.answerer_, request.clone(), silent_timeout, limit, result);
    }
    h.wait_for([&] { return held->count() == silent_count; },
               "full silent batch not delivered");
    h.run([&] {
      held->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
    });
    h.wait_for([&] { return h.outbound(h.answerer_).live == silent_count; },
               "silent responses did not saturate connection");
    auto saturated_at = td::Timestamp::now();
    for (unsigned i = 0; i < healthy_count; ++i) {
      auto healthy =
          std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
      h.run([&] {
        td::actor::send_closure(
            h.rldp_, &tos::rldp2::Rldp::send_query_ex, h.buffered_, h.answerer_,
            std::string("healthy"),
            [healthy](td::Result<td::BufferSlice> result) {
              *healthy = std::move(result);
            },
            td::Timestamp::in(healthy_timeout), request.clone(), limit);
      });
      h.wait_for([&] { return held->count() == 1; }, "healthy query starved");
      h.run([&] {
        held->release(td::BufferSlice(std::string(bytes, '*')),
                      td::Timestamp{});
      });
      h.wait_for([&] { return healthy->has_value(); },
                 "healthy response starved");
      CHECK((*healthy)->is_ok() &&
            (*healthy)->ok().as_slice() == std::string(bytes, '*'));
      h.wait_for(
          [&] {
            return h.outbound(h.answerer_).live == silent_count &&
                   h.outbound(h.buffered_).live == 0;
          },
          "healthy transfer not retired");
    }
    CHECK(td::Timestamp::now().at() - saturated_at.at() < 10);
    for (auto &result : silent)
      CHECK(!result->has_value());
    h.requester_receives(true);
    h.wait_for(
        [&] {
          for (auto &result : silent)
            if (!result->has_value())
              return false;
          return h.outbound(h.answerer_).live == 0 &&
                 h.outbound(h.requester_).live == 0;
        },
        "silent batch did not recover", 10);
    for (auto &result : silent)
      CHECK((*result)->is_ok() &&
            (*result)->ok().as_slice() == std::string(bytes, '*'));
    auto started = h.outbound(h.answerer_).started - baseline;
    CHECK(started == (round + 1) * (silent_count + healthy_count));
    std::cout << "{\"round\":" << round + 1
              << ",\"silent_peak\":256,\"healthy_completed\":"
              << (round + 1) * healthy_count
              << ",\"silent_completed\":" << (round + 1) * silent_count
              << ",\"started\":" << started << ",\"retained\":0}\n";
  }
}
