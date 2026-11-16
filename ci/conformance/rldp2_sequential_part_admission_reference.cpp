// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
struct Sink : tos::rldp2::ConnectionCallback {
  unsigned deliveries{0}, completes{0};
  void send_raw(td::BufferSlice bytes) override {
    auto obj = tos::fetch_tl_object<tos::tos_api::rldp2_MessagePart>(
        bytes.as_slice(), true);
    CHECK(obj.is_ok());
    if (obj.ok()->get_id() == tos::tos_api::rldp2_complete::ID)
      ++completes;
  }
  void receive(tos::rldp2::TransferId, td::Result<td::BufferSlice>) override {
    ++deliveries;
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {}
};
int main() {
  tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
  tos::rldp2::TransferId id;
  id.set_zero();
  CHECK(connection.set_receive_limits(id, td::Timestamp::in(10), 4000001));
  Sink sink;
  unsigned part;
  while (std::cin >> part) {
    CHECK(part <= 2);
    auto encoder = td::fec::RaptorQEncoder::create(
        td::BufferSlice(std::string(part < 2 ? 2000000 : 1, '*')), 768);
    encoder->prepare_more_symbols();
    tos::fec::FecType fec{encoder->get_parameters()};
    connection.receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            id, fec.tl(), part, 4000001, 0, encoder->gen_symbol(0).data));
    connection.run(sink);
    std::cout << "{\"part\":" << part
              << ",\"active\":" << connection.inbound_transfer_count()
              << ",\"completed\":" << connection.completed_transfer_count()
              << ",\"complete_packets\":" << sink.completes
              << ",\"deliveries\":" << sink.deliveries << "}\n";
  }
}
