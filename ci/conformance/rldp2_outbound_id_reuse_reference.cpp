// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "rldp2/RldpConnection.h"
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>
struct Observer : tos::rldp2::ConnectionCallback {
  std::vector<td::BufferSlice> wire;
  unsigned completed{0}, delivered{0};
  void send_raw(td::BufferSlice packet) override {
    wire.push_back(std::move(packet));
  }
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> data) override {
    CHECK(data.is_ok() &&
          data.ok().as_slice() == td::Slice(std::string(64, '*')));
    ++delivered;
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit> result) override {
    CHECK(result.is_ok());
    ++completed;
  }
};
int main() {
  unsigned bytes, replacement, timeout;
  CHECK(bool(std::cin >> bytes >> replacement >> timeout));
  CHECK(bytes == 64 && replacement == 65 && timeout == 60);
  tos::rldp2::RldpConnection sender{tos::rldp2::RldpPeerIdentity{}};
  tos::rldp2::RldpConnection receiver{tos::rldp2::RldpPeerIdentity{}};
  Observer outgoing, incoming;
  tos::rldp2::TransferId id;
  id.as_slice().fill(7);
  sender.send(id, td::BufferSlice(std::string(bytes, '*')),
              td::Timestamp::in(timeout));
  sender.run(outgoing);
  CHECK(!outgoing.wire.empty() && sender.outbound_transfer_count() == 1);
  auto before = sender.outbound_transfers_started();
  sender.send(id, td::BufferSlice(std::string(replacement, '*')),
              td::Timestamp::in(timeout));
  auto after = sender.outbound_transfers_started();
  CHECK(before == 1 && after == 1 && sender.outbound_transfer_count() == 1);
  auto limit = td::Timestamp::in(5);
  while (outgoing.completed != 1 && !limit.is_in_past()) {
    for (auto &packet : outgoing.wire)
      receiver.receive_raw(std::move(packet));
    outgoing.wire.clear();
    receiver.run(incoming);
    for (auto &packet : incoming.wire)
      sender.receive_raw(std::move(packet));
    incoming.wire.clear();
    sender.run(outgoing);
    if (outgoing.completed != 1)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  CHECK(outgoing.completed == 1 && incoming.delivered == 1 &&
        sender.outbound_transfer_count() == 0);
  std::cout << "{\"started_before\":" << before
            << ",\"started_after_replay\":" << after
            << ",\"completed\":" << outgoing.completed
            << ",\"retained\":" << sender.outbound_transfer_count() << "}\n";
}
