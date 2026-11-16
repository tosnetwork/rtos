// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
struct Sink : tos::rldp2::ConnectionCallback {
  unsigned errors{0}, deliveries{0};
  void send_raw(td::BufferSlice) override {}
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> data) override {
    if (data.is_error())
      ++errors;
    else
      ++deliveries;
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {}
};
int main() {
  std::string name;
  int length, seqno, warm;
  bool first = true;
  std::cout << "[";
  while (std::cin >> name >> length >> seqno >> warm) {
    CHECK(length >= 0 && length <= 769 && seqno >= -1 && warm <= 40);
    tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
    auto encoder = td::fec::RaptorQEncoder::create(
        td::BufferSlice(std::string(2048, '*')), 768);
    encoder->prepare_more_symbols();
    tos::fec::FecType fec{encoder->get_parameters()};
    tos::rldp2::TransferId id;
    id.set_zero();
    Sink sink;
    if (warm >= 0) {
      connection.receive_raw(
          tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
              id, fec.tl(), 0, 2048, warm, encoder->gen_symbol(warm).data));
      connection.run(sink);
      CHECK(connection.inbound_transfer_count() == 1 && sink.errors == 0 &&
            sink.deliveries == 0);
    }
    connection.receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            id, fec.tl(), 0, 2048, seqno,
            td::BufferSlice(std::string(length, '*'))));
    connection.run(sink);
    if (!first)
      std::cout << ",";
    first = false;
    std::cout << "{\"id\":\"" << name << "\",\"errors\":" << sink.errors
              << ",\"deliveries\":" << sink.deliveries
              << ",\"inbound\":" << connection.inbound_transfer_count()
              << ",\"completed\":" << connection.completed_transfer_count()
              << "}";
  }
  std::cout << "]\n";
}
