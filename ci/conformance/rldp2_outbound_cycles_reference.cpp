// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "rldp2/RldpConnection.h"
#include "tl-utils/tl-utils.hpp"
#include <chrono>
#include <iostream>
#include <set>
#include <thread>
#include <vector>
struct Observer : tos::rldp2::ConnectionCallback {
  td::BufferSlice expected;
  std::vector<td::BufferSlice> wire;
  std::set<tos::rldp2::TransferId> completed, delivered;
  explicit Observer(td::BufferSlice data) : expected(std::move(data)) {}
  void send_raw(td::BufferSlice packet) override {
    wire.push_back(std::move(packet));
  }
  void receive(tos::rldp2::TransferId id,
               td::Result<td::BufferSlice> data) override {
    CHECK(data.is_ok() && data.ok().as_slice() == expected.as_slice());
    CHECK(delivered.insert(id).second);
  }
  void on_sent(tos::rldp2::TransferId id,
               td::Result<td::Unit> result) override {
    CHECK(result.is_ok());
    CHECK(completed.insert(id).second);
  }
};
int main() {
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  unsigned rounds, capacity, bytes, timeout;
  CHECK(bool(std::cin >> rounds >> capacity >> bytes >> timeout));
  CHECK(rounds == 32 && capacity == 256 && bytes == 64 && timeout == 60);
  td::Bits256 zero;
  zero.set_zero();
  auto data = tos::create_serialize_tl_object<tos::tos_api::rldp_message>(
      zero, td::BufferSlice("mtu:" + std::string(23, '*')));
  CHECK(data.size() == bytes);
  tos::rldp2::RldpConnection sender{tos::rldp2::RldpPeerIdentity{}};
  tos::rldp2::RldpConnection receiver{tos::rldp2::RldpPeerIdentity{}};
  Observer outgoing(data.clone()), incoming(data.clone());
  std::set<tos::rldp2::TransferId> accepted;
  for (unsigned round = 0; round < rounds; ++round) {
    for (unsigned n = 0; n <= capacity; ++n) {
      unsigned serial = round * (capacity + 1) + n + 1;
      tos::rldp2::TransferId id;
      id.as_slice().fill(7);
      for (unsigned b = 0; b < 4; ++b)
        id.as_slice()[b] = static_cast<char>(serial >> (8 * b));
      sender.send(id, data.clone(), td::Timestamp::in(timeout));
      if (n < capacity)
        CHECK(accepted.insert(id).second);
    }
    CHECK(sender.outbound_transfer_count() == capacity);
    CHECK(sender.outbound_transfers_started() == accepted.size());
    auto deadline = td::Timestamp::in(10);
    while (outgoing.completed.size() != accepted.size() &&
           !deadline.is_in_past()) {
      sender.run(outgoing);
      for (auto &packet : outgoing.wire)
        receiver.receive_raw(std::move(packet));
      outgoing.wire.clear();
      receiver.run(incoming);
      for (auto &packet : incoming.wire)
        sender.receive_raw(std::move(packet));
      incoming.wire.clear();
      sender.run(outgoing);
      if (outgoing.completed.size() != accepted.size())
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(outgoing.completed == accepted && incoming.delivered == accepted);
    CHECK(sender.outbound_transfer_count() == 0);
    CHECK(sender.inbound_transfer_count() == 0 &&
          receiver.inbound_transfer_count() == 0);
    CHECK(receiver.completed_transfer_count() <= 2048);
    std::cout << "{\"round\":" << round + 1
              << ",\"submitted\":257,\"peak\":256,\"completed\":"
              << outgoing.completed.size()
              << ",\"delivered\":" << incoming.delivered.size()
              << ",\"retained\":0}\n";
  }
}
