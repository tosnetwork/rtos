// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <thread>
struct Sink : tos::rldp2::ConnectionCallback {
  unsigned errors{0}, deliveries{0}, completes{0}, received{0};
  void send_raw(td::BufferSlice bytes) override {
    auto obj = tos::fetch_tl_object<tos::tos_api::rldp2_MessagePart>(
        bytes.as_slice(), true);
    CHECK(obj.is_ok());
    if (obj.ok()->get_id() == tos::tos_api::rldp2_complete::ID)
      ++completes;
    if (obj.ok()->get_id() == tos::tos_api::rldp2_confirm::ID) {
      auto &ack = static_cast<tos::tos_api::rldp2_confirm &>(*obj.ok());
      received = std::max(received, static_cast<unsigned>(ack.received_count_));
    }
  }
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> value) override {
    if (value.is_error())
      ++errors;
    else
      ++deliveries;
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {}
};
int main() {
  std::string name;
  unsigned original, changed, part, bytes, seq;
  while (std::cin >> name >> original >> changed >> part >> bytes >> seq) {
    tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
    tos::rldp2::TransferId id;
    id.set_zero();
    CHECK(connection.set_receive_limits(id, td::Timestamp::in(10), 4000001));
    Sink sink;
    auto send = [&](unsigned total, unsigned index, unsigned size,
                    unsigned sequence) {
      auto encoder = td::fec::RaptorQEncoder::create(
          td::BufferSlice(std::string(size, '*')), 768);
      encoder->prepare_more_symbols();
      tos::fec::FecType fec{encoder->get_parameters()};
      connection.receive_raw(
          tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
              id, fec.tl(), index, total, sequence,
              encoder->gen_symbol(sequence).data));
      connection.run(sink);
    };
    send(original, 0, 2000000, 0);
    send(changed, part, bytes, seq);
    send(changed, part, bytes, seq);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    connection.run(sink);
    std::cout << "{\"id\":\"" << name
              << "\",\"active\":" << connection.inbound_transfer_count()
              << ",\"completed\":" << connection.completed_transfer_count()
              << ",\"errors\":" << sink.errors
              << ",\"deliveries\":" << sink.deliveries
              << ",\"complete_packets\":" << sink.completes
              << ",\"max_received\":" << sink.received << "}\n";
  }
}
