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
  unsigned count, bytes, timeout;
  CHECK(bool(std::cin >> count >> bytes >> timeout));
  CHECK(count == 2049 && bytes == 64 && timeout == 60);
  tos::rldp2::RldpConnection sender{tos::rldp2::RldpPeerIdentity{}};
  tos::rldp2::RldpConnection receiver{tos::rldp2::RldpPeerIdentity{}};
  Observer outgoing, incoming;
  for (unsigned i = 0; i < count; ++i) {
    tos::rldp2::TransferId id;
    id.set_zero();
    id.as_slice().copy_from(
        td::Slice(reinterpret_cast<const char *>(&i), sizeof(i)));
    sender.send(id, td::BufferSlice(std::string(bytes, '*')),
                td::Timestamp::in(timeout));
    auto limit = td::Timestamp::in(5);
    while (outgoing.completed != i + 1 && !limit.is_in_past()) {
      sender.run(outgoing);
      for (auto &packet : outgoing.wire)
        receiver.receive_raw(std::move(packet));
      outgoing.wire.clear();
      receiver.run(incoming);
      for (auto &packet : incoming.wire)
        sender.receive_raw(std::move(packet));
      incoming.wire.clear();
      sender.run(outgoing);
      if (outgoing.completed != i + 1)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(outgoing.completed == i + 1 && incoming.delivered == i + 1);
    CHECK(sender.outbound_transfer_count() == 0);
  }
  std::cout << "{\"completed\":" << outgoing.completed
            << ",\"outbound_retained\":" << sender.outbound_transfer_count()
            << ",\"completed_inbound\":" << sender.completed_transfer_count()
            << "}\n";
}
