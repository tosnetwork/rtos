/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with TOS Blockchain.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give permission
    to link the code of portions of this program with the OpenSSL library.
    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the file(s),
    but you are not obligated to do so. If you do not wish to do so, delete this
    exception statement from your version. If you delete this exception
   statement from all source files in the program, then also delete it here.

    Copyright 2017-2020 Telegram Systems LLP
    Copyright 2025-2026 TOS Blockchain Teams
*/
#include "adnl/adnl-test-loopback-implementation.h"
#include "adnl/adnl.h"
#include "auto/tl/tos_api.hpp"
#include "rldp2/rldp.h"
#include "td/utils/port/signals.h"
#include "tl-utils/tl-utils.hpp"
#include <cctype>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <sstream>

struct Case {
  std::string id;
  unsigned direction;
  td::uint32 size;
  td::uint64 limit;
};

int main(int argc, char **argv) {
  CHECK(argc == 2);
  std::vector<Case> cases;
  for (std::string line; std::getline(std::cin, line);) {
    if (line.empty() || line[0] == '#')
      continue;
    std::istringstream input(line);
    Case c;
    CHECK(bool(input >> c.id >> c.direction >> c.size >> c.limit));
    std::string extra;
    CHECK(!(input >> extra));
    CHECK(!c.id.empty());
    for (unsigned char ch : c.id)
      CHECK(std::isalnum(ch) || ch == '_');
    CHECK(c.direction < 2 && c.size <= 2 * 1024 * 1024 &&
          c.limit <= 2 * 1024 * 1024);
    cases.push_back(c);
    CHECK(cases.size() <= 100);
  }
  CHECK(!cases.empty());
  std::string db_root_ = argv[1];
  CHECK(std::filesystem::create_directory(db_root_));
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();
  td::actor::ActorOwn<tos::keyring::Keyring> keyring;
  td::actor::ActorOwn<tos::adnl::TestLoopbackNetworkManager> network_manager;
  td::actor::ActorOwn<tos::adnl::Adnl> adnl;
  td::actor::ActorOwn<tos::rldp2::Rldp> rldp;

  tos::adnl::AdnlNodeIdShort src;
  tos::adnl::AdnlNodeIdShort dst;

  td::actor::Scheduler scheduler({0});

  scheduler.run_in_context([&] {
    keyring = tos::keyring::Keyring::create(db_root_);
    network_manager =
        td::actor::create_actor<tos::adnl::TestLoopbackNetworkManager>(
            "test net");
    adnl = tos::adnl::Adnl::create(db_root_, keyring.get());
    rldp = tos::rldp2::Rldp::create(adnl.get());
    td::actor::send_closure(adnl, &tos::adnl::Adnl::register_network_manager,
                            network_manager.get());

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

    auto addr =
        tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list();

    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id,
                            tos::adnl::AdnlNodeIdFull{pub1}, addr,
                            td::uint8(0));
    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_id,
                            tos::adnl::AdnlNodeIdFull{pub2}, addr,
                            td::uint8(0));
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::add_id, src);
    td::actor::send_closure(rldp, &tos::rldp2::Rldp::add_id, dst);

    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_peer, src,
                            tos::adnl::AdnlNodeIdFull{pub2}, addr);
    td::actor::send_closure(adnl, &tos::adnl::Adnl::add_peer, dst,
                            tos::adnl::AdnlNodeIdFull{pub1}, addr);

    td::actor::send_closure(network_manager,
                            &tos::adnl::TestLoopbackNetworkManager::add_node_id,
                            src, true, true);
    td::actor::send_closure(network_manager,
                            &tos::adnl::TestLoopbackNetworkManager::add_node_id,
                            dst, true, true);
  });

  class Callback : public tos::adnl::Adnl::Callback {
  public:
    void receive_message(tos::adnl::AdnlNodeIdShort, tos::adnl::AdnlNodeIdShort,
                         td::BufferSlice) override {}
    void receive_query(tos::adnl::AdnlNodeIdShort, tos::adnl::AdnlNodeIdShort,
                       td::BufferSlice data,
                       td::Promise<td::BufferSlice> promise) override {
      auto query = tos::fetch_tl_object<tos::tos_api::overlay_query>(
          data.as_slice(), true);
      query.ensure();
      const td::Slice bytes = query.ok()->overlay_.as_slice();
      td::uint32 size = 0;
      for (unsigned i = 0; i < 4; ++i)
        size |= td::uint32(static_cast<unsigned char>(bytes[i])) << (8 * i);
      CHECK(size <= 2 * 1024 * 1024);
      td::BufferSlice reply(size);
      for (td::uint32 i = 0; i < size; ++i)
        reply.as_slice()[i] = static_cast<char>(i % 251);
      promise.set_value(std::move(reply));
    }
  };
  td::Bits256 prefix_id;
  prefix_id.set_zero();
  auto prefix_data = tos::serialize_tl_object(
      tos::create_tl_object<tos::tos_api::overlay_query>(prefix_id), true);
  const auto prefix = prefix_data.as_slice().truncate(4).str();
  scheduler.run_in_context([&] {
    td::actor::send_closure(adnl, &tos::adnl::Adnl::subscribe, src, prefix,
                            std::make_unique<Callback>());
    td::actor::send_closure(adnl, &tos::adnl::Adnl::subscribe, dst, prefix,
                            std::make_unique<Callback>());
  });
  for (const auto &c : cases) {
    const auto started = std::chrono::steady_clock::now();
    td::Bits256 request;
    request.set_zero();
    for (unsigned i = 0; i < 4; ++i)
      request.as_slice()[i] = static_cast<char>(c.size >> (8 * i));
    bool done = false;
    std::string status, payload;
    int error_code = 0;
    scheduler.run_in_context([&] {
      td::actor::send_closure(
          rldp, &tos::rldp2::Rldp::send_query_ex, c.direction ? dst : src,
          c.direction ? src : dst, std::string("runtime-probe"),
          td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> result) {
            if (result.is_error()) {
              error_code = result.error().code();
              status =
                  error_code == tos::ErrorCode::timeout ? "timeout" : "error";
            } else {
              status = "answer";
              constexpr char digits[] = "0123456789abcdef";
              for (unsigned char ch : result.ok().as_slice()) {
                payload += digits[ch >> 4];
                payload += digits[ch & 15];
              }
            }
            done = true;
          }),
          td::Timestamp::in(10.0),
          tos::serialize_tl_object(
              tos::create_tl_object<tos::tos_api::overlay_query>(request),
              true),
          c.limit);
    });
    auto deadline = td::Timestamp::in(30.0);
    while (!done && !deadline.is_in_past())
      scheduler.run(0.001);
    CHECK(done);
    std::cout << "{\"id\":\"" << c.id << "\",\"status\":\"" << status
              << "\",\"payload_hex\":\"" << payload
              << "\",\"error_code\":" << error_code << ",\"elapsed_ms\":"
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now() - started)
                     .count()
              << "}\n"
              << std::flush;
  }
  scheduler.run_in_context([&] {
    rldp.reset();
    adnl.reset();
    network_manager.reset();
    keyring.reset();
  });
  return 0;
}
