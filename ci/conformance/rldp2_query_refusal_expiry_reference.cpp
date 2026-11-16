/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// Use the validated native loopback setup without warm transfers, then freeze
// time to verify that a refusal does not extend an admitted connection expiry.

#include <chrono>
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
  auto deadline =
      std::chrono::steady_clock::now() + std::chrono::duration<double>(seconds);
  while (std::chrono::steady_clock::now() < deadline && !(done && done())) {
    scheduler.run(0.001);
  }
}

} // namespace

int main(int argc, char **argv) {
  td::Time::allow_freezes();
  CHECK(argc == 2);
  unsigned count;
  double query_timeout, refusal_at, expiry_at;
  CHECK(bool(std::cin >> count >> query_timeout >> refusal_at >> expiry_at));
  CHECK(count == 256 && query_timeout == 10 && refusal_at == 1 &&
        expiry_at == 130.5);
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

  // Nothing is delivered from here on, so the query below can never complete
  // by itself.
  scheduler.run_in_context([&] {
    td::actor::send_closure(
        network_manager,
        &tos::adnl::TestLoopbackNetworkManager::set_loss_probability, 1.0);
  });

  run_for(scheduler,
          0.05); // Drain setup before freezing; no warm query transfers.
  td::Time::freeze();
  const auto start = td::Time::now();
  auto refused = std::make_shared<unsigned>(0);
  auto query = [&] {
    td::actor::send_closure(
        rldp, &tos::rldp2::Rldp::send_query_ex, src, dst,
        std::string("pending"),
        td::PromiseCreator::lambda([refused](td::Result<td::BufferSlice> r) {
          if (r.is_error() && r.error().message().str().find(
                                  "from this peer") != std::string::npos)
            ++*refused;
        }),
        td::Timestamp::in(query_timeout), td::BufferSlice("x"), 1024);
  };
  auto stats = [&] {
    tos::rldp2::Rldp::ConnectionStats result;
    bool ready = false;
    scheduler.run_in_context([&] {
      td::actor::send_closure(
          rldp, &tos::rldp2::Rldp::get_connection_stats,
          td::PromiseCreator::lambda(
              [&](td::Result<tos::rldp2::Rldp::ConnectionStats> r) {
                r.ensure();
                result = r.move_as_ok();
                ready = true;
              }));
    });
    run_for(scheduler, 1, [&] { return ready; });
    CHECK(ready);
    return result;
  };
  auto local_live = [&](const tos::rldp2::Rldp::ConnectionStats &s) {
    for (const auto &[id, count] : s.per_local_id)
      if (id == src)
        return count;
    return size_t{0};
  };
  scheduler.run_in_context([&] {
    for (unsigned i = 0; i < count; ++i)
      query();
  });
  auto before = stats();
  CHECK(before.pending_queries == 256 && local_live(before) == 1);
  td::Time::jump_in_future(start + refusal_at);
  scheduler.run_in_context(query);
  auto after = stats();
  CHECK(*refused == 1 && after.pending_queries == 256 &&
        local_live(after) == 1);
  td::Time::jump_in_future(start + expiry_at);
  run_for(scheduler, 0.05);
  auto expired = stats();
  CHECK(local_live(expired) == 0);
  std::cout << "{\"refused\":" << *refused
            << ",\"live_after_original_expiry\":" << local_live(expired)
            << "}\n";
  scheduler.run_in_context([&] {
    rldp.reset();
    adnl.reset();
    network_manager.reset();
    keyring.reset();
  });
  td::Time::unfreeze();
  return 0;
}
