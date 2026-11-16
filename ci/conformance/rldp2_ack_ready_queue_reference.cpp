// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <chrono>
#include <iostream>
#include <thread>
struct Sink : tos::rldp2::ConnectionCallback {
  unsigned confirms{0}, deliveries{0};
  void send_raw(td::BufferSlice bytes) override {
    auto obj = tos::fetch_tl_object<tos::tos_api::rldp2_MessagePart>(
        bytes.as_slice(), true);
    CHECK(obj.is_ok());
    if (obj.ok()->get_id() == tos::tos_api::rldp2_confirm::ID)
      ++confirms;
  }
  void receive(tos::rldp2::TransferId, td::Result<td::BufferSlice>) override {
    ++deliveries;
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {}
};
int main() {
  unsigned queued;
  while (std::cin >> queued) {
    CHECK(queued > 0 && queued <= 64);
    tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
    auto encoder = td::fec::RaptorQEncoder::create(
        td::BufferSlice(std::string(2048, '*')), 768);
    encoder->prepare_more_symbols();
    tos::fec::FecType fec{encoder->get_parameters()};
    tos::rldp2::TransferId id;
    id.set_zero();
    Sink sink;
    auto send = [&] {
      connection.receive_raw(
          tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
              id, fec.tl(), 0, 2048, 0, encoder->gen_symbol(0).data));
    };
    send();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    // Each scheduled connection turn can flush an overdue ACK while more
    // duplicate packets remain ready. No idle interval is needed between them.
    for (unsigned i = 0; i < queued; ++i) {
      connection.run(sink);
      send();
    }
    std::cout << "{\"queued\":" << queued
              << ",\"ack_progress\":" << (sink.confirms > 0 ? "true" : "false")
              << ",\"deliveries\":" << sink.deliveries << "}\n";
  }
}
