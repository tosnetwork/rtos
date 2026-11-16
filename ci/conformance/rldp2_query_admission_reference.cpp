/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// Derived from TOS test-rldp2-query-eviction.cpp. Retain its eight-query
// loopback control, then freeze pending-query admission at both native caps.
// Connection-flood and eviction phases of the original test are not run here.

#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>

#include "adnl/adnl-test-loopback-implementation.h"
#include "adnl/adnl.h"
#include "keyring/keyring.h"
#include "rldp2/rldp.h"
#include "td/utils/Time.h"
#include "td/utils/port/path.h"
#include "td/utils/port/signals.h"

namespace {

tos::adnl::AdnlNodeIdShort fabricated_peer(td::uint32 n) {
  td::Bits256 bits;
  bits.set_zero();
  bits.as_slice().copy_from(
      td::Slice{reinterpret_cast<const td::uint8 *>(&n), sizeof(n)});
  return tos::adnl::AdnlNodeIdShort{bits};
}

// Scheduler::run(timeout) is one pass over the actors that are ready now,
// waiting at most `timeout` for some to become ready; it is not "run for
// `timeout` seconds". An actor that yields is queued again and runs only in a
// later pass -- and the RLDP2 connection actor yields after every send, so a
// harness that calls run() once per phase lets each connection handle one
// send and nothing more. Run passes until the deadline, or until `done`.
void run_for(td::actor::Scheduler &scheduler, double seconds,
             const std::function<bool()> &done = {}) {
  auto deadline = td::Timestamp::in(seconds);
  while (!deadline.is_in_past() && !(done && done())) {
    scheduler.run(0.001);
  }
}

} // namespace

int main(int argc, char **argv) {
  CHECK(argc == 2);
  unsigned count;
  CHECK(bool(std::cin >> count) && count == 257);
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();

  std::string db_root = argv[1];
  td::rmrf(db_root).ignore();
  td::mkdir(db_root).ensure();

  td::actor::ActorOwn<tos::keyring::Keyring> keyring;
  td::actor::ActorOwn<tos::adnl::TestLoopbackNetworkManager> network_manager;
  td::actor::ActorOwn<tos::adnl::Adnl> adnl;
  td::actor::ActorOwn<tos::rldp2::Rldp> rldp;
  tos::adnl::AdnlNodeIdShort src;
  tos::adnl::AdnlNodeIdShort dst;

  td::actor::Scheduler scheduler({0});

  scheduler.run_in_context([&] {
    keyring = tos::keyring::Keyring::create(db_root);
    network_manager =
        td::actor::create_actor<tos::adnl::TestLoopbackNetworkManager>(
            "test net");
    adnl = tos::adnl::Adnl::create(db_root, keyring.get());
    rldp = tos::rldp2::Rldp::create(adnl.get());
    td::actor::send_closure(adnl, &tos::adnl::Adnl::register_network_manager,
                            network_manager.get());

    auto addr =
        tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();
    auto pk1 = tos::PrivateKey{tos::privkeys::Ed25519::random()};
    auto pub1 = pk1.compute_public_key();
    src = tos::adnl::AdnlNodeIdShort{pub1.compute_short_id()};
    td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key,
                            std::move(pk1), true, [](td::Result<>) {});

    auto pk2 = tos::PrivateKey{tos::privkeys::Ed25519::random()};
    auto pub2 = pk2.compute_public_key();
    dst = tos::adnl::AdnlNodeIdShort{pub2.compute_short_id()};
    td::actor::send_closure(keyring, &tos::keyring::Keyring::add_key,
                            std::move(pk2), true, [](td::Result<>) {});

    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id,
                            tos::adnl::AdnlNodeIdFull{pub1}, addr,
                            td::uint8(0));
    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id,
                            tos::adnl::AdnlNodeIdFull{pub2}, addr,
                            td::uint8(0));
    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_peer, src,
                            tos::adnl::AdnlNodeIdFull{pub2}, addr);
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::add_id, src);
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::add_id, dst);
    td::actor::send_closure(network_manager,
                            &tos::adnl::TestLoopbackNetworkManager::add_node_id,
                            src, true, true);
    td::actor::send_closure(network_manager,
                            &tos::adnl::TestLoopbackNetworkManager::add_node_id,
                            dst, true, true);

    class Answerer : public tos::adnl::Adnl::Callback {
    public:
      void receive_message(tos::adnl::AdnlNodeIdShort,
                           tos::adnl::AdnlNodeIdShort,
                           td::BufferSlice) override {}
      void receive_query(tos::adnl::AdnlNodeIdShort, tos::adnl::AdnlNodeIdShort,
                         td::BufferSlice data,
                         td::Promise<td::BufferSlice> promise) override {
        promise.set_value(
            td::BufferSlice(PSLICE() << "answer to " << data.as_slice()));
      }
    };
    td::actor::send_closure(adnl, &tos::adnl::Adnl::subscribe, dst, "ask",
                            std::make_unique<Answerer>());
  });

  auto fail = [&](td::Slice what) {
    LOG(ERROR) << "FAILED: " << what;
    td::rmrf(db_root).ignore();
    std::exit(1);
  };

  // The control: several queries in one burst over one connection, every one
  // answered, with delivery on.
  constexpr int kControlQueries = 8;
  int control_answered = 0;
  int control_wrong = 0;
  scheduler.run_in_context([&] {
    for (int i = 0; i < kControlQueries; i++) {
      auto question = "ask" + std::to_string(i);
      td::actor::send_closure(
          rldp, &tos::rldp2::Rldp::send_query_ex, src, dst,
          std::string("control"),
          td::PromiseCreator::lambda(
              [&, question](td::Result<td::BufferSlice> R) {
                if (R.is_ok() &&
                    R.ok().as_slice() == td::Slice("answer to " + question)) {
                  ++control_answered;
                } else {
                  ++control_wrong;
                }
              }),
          td::Timestamp::in(30.0), td::BufferSlice(question), 1 << 20);
    }
  });
  run_for(scheduler, 20.0,
          [&] { return control_answered + control_wrong == kControlQueries; });
  LOG(ERROR) << "control: " << control_answered << " of " << kControlQueries
             << " queries answered, " << control_wrong << " wrong or failed";
  if (control_answered != kControlQueries || control_wrong != 0) {
    fail("one connection did not carry a burst of queries to their answers");
  }

  size_t warm_pending = 1;
  bool warm_stats_done = false;
  scheduler.run_in_context([&] {
    td::actor::send_closure(
        rldp, &tos::rldp2::Rldp::get_connection_stats,
        td::PromiseCreator::lambda(
            [&](td::Result<tos::rldp2::Rldp::ConnectionStats> r) {
              r.ensure();
              warm_pending = r.ok().pending_queries;
              warm_stats_done = true;
            }));
  });
  run_for(scheduler, 1.0, [&] { return warm_stats_done; });
  CHECK(warm_stats_done && warm_pending == 0);

  // Nothing is delivered from here on, so the query below can never complete
  // by itself.
  scheduler.run_in_context([&] {
    td::actor::send_closure(
        network_manager,
        &tos::adnl::TestLoopbackNetworkManager::set_loss_probability, 1.0);
  });

  struct Result {
    unsigned refused{0}, other{0};
  };
  auto result = std::make_shared<Result>();
  scheduler.run_in_context([&] {
    for (unsigned i = 0; i < count; ++i) {
      td::actor::send_closure(
          rldp, &tos::rldp2::Rldp::send_query_ex, src, dst,
          std::string("pending"),
          td::PromiseCreator::lambda([result](td::Result<td::BufferSlice> r) {
            if (r.is_error() && r.error().message().str().find(
                                    "from this peer") != std::string::npos)
              ++result->refused;
            else
              ++result->other;
          }),
          td::Timestamp::in(60), td::BufferSlice("x"), 1024);
    }
  });
  run_for(scheduler, 1.0, [&] { return result->refused == 1; });
  size_t pending = 0;
  bool stats_done = false;
  scheduler.run_in_context([&] {
    td::actor::send_closure(
        rldp, &tos::rldp2::Rldp::get_connection_stats,
        td::PromiseCreator::lambda(
            [&](td::Result<tos::rldp2::Rldp::ConnectionStats> r) {
              r.ensure();
              pending = r.ok().pending_queries;
              stats_done = true;
            }));
  });
  run_for(scheduler, 1.0, [&] { return stats_done; });
  CHECK(stats_done && pending == 256 && result->refused == 1 &&
        result->other == 0);
  auto global = std::make_shared<Result>();
  scheduler.run_in_context([&] {
    for (unsigned peer = 1; peer <= 32; ++peer) {
      for (unsigned i = 0; i < (peer == 32 ? 1u : 256u); ++i) {
        td::actor::send_closure(
            rldp, &tos::rldp2::Rldp::send_query_ex, src, fabricated_peer(peer),
            std::string("global"),
            td::PromiseCreator::lambda([global](td::Result<td::BufferSlice> r) {
              if (r.is_error() &&
                  r.error().message().str() ==
                      "too many RLDP queries are already awaiting an answer")
                ++global->refused;
              else
                ++global->other;
            }),
            td::Timestamp::in(60), td::BufferSlice("x"), 1024);
      }
    }
  });
  run_for(scheduler, 3.0, [&] { return global->refused == 1; });
  size_t global_pending = 0;
  stats_done = false;
  scheduler.run_in_context([&] {
    td::actor::send_closure(
        rldp, &tos::rldp2::Rldp::get_connection_stats,
        td::PromiseCreator::lambda(
            [&](td::Result<tos::rldp2::Rldp::ConnectionStats> r) {
              r.ensure();
              global_pending = r.ok().pending_queries;
              stats_done = true;
            }));
  });
  run_for(scheduler, 1.0, [&] { return stats_done; });
  CHECK(stats_done && global_pending == 8192 && global->refused == 1 &&
        global->other == 0);
  std::cout << "{\"warm_pending\":" << warm_pending
            << ",\"pending\":" << pending << ",\"refused\":" << result->refused
            << ",\"other\":" << result->other
            << ",\"global_pending\":" << global_pending
            << ",\"global_refused\":" << global->refused
            << ",\"global_other\":" << global->other << "}\n";
  scheduler.run_in_context([&] {
    rldp.reset();
    adnl.reset();
    network_manager.reset();
    keyring.reset();
  });
  return 0;
}
