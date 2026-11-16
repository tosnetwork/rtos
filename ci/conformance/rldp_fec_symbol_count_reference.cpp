// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
struct Sink : tos::rldp2::ConnectionCallback {
  unsigned complete_packets{0}, replay_packets{0};
  void send_raw(td::BufferSlice packet) override {
    auto object = tos::fetch_tl_object<tos::tos_api::rldp2_MessagePart>(
        packet.as_slice(), true);
    CHECK(object.is_ok());
    if (object.ok()->get_id() == tos::tos_api::rldp2_complete::ID) {
      ++complete_packets;
      if (static_cast<tos::tos_api::rldp2_complete &>(*object.ok()).part_ == 1)
        ++replay_packets;
    }
  }
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> data) override {
    CHECK(data.is_ok());
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {}
};
int main() {
  std::string name;
  int count;
  int part = 0, total = 2048, bytes = 2048;
  bool first = true;
  std::cout << "[";
  while (std::cin >> name >> count) {
    CHECK(part >= 0 && part <= 1 && total > 0 && total <= 2048 && bytes > 0 &&
          bytes <= 2048);
    tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
    auto encoder = td::fec::RaptorQEncoder::create(
        td::BufferSlice(std::string(bytes, '*')), 768);
    encoder->prepare_more_symbols();
    tos::fec::FecType fec{encoder->get_parameters()};
    tos::rldp2::TransferId id;
    id.set_zero();
    Sink sink;
    auto before_replay = sink.replay_packets;
    connection.receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            id,
            tos::create_tl_object<tos::tos_api::fec_raptorQ>(bytes, 768, count),
            part, total, 0, encoder->gen_symbol(0).data));
    connection.run(sink);
    if (!first)
      std::cout << ",";
    first = false;
    std::cout << "{\"id\":\"" << name
              << "\",\"inbound\":" << connection.inbound_transfer_count()
              << ",\"completed\":" << connection.completed_transfer_count()
              << ",\"replay_complete_packets\":"
              << (sink.replay_packets - before_replay) << "}";
  }
  std::cout << "]\n";
}
