// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
struct Observer : tos::rldp2::ConnectionCallback {
  unsigned completed{0}, delivered{0};
  td::BufferSlice expected;
  void send_raw(td::BufferSlice) override {}
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> data) override {
    CHECK(data.is_ok() && data.ok().as_slice() == expected.as_slice());
    ++delivered;
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit> result) override {
    CHECK(result.is_ok());
    ++completed;
  }
};
int main() {
  unsigned bytes, timeout;
  CHECK(bool(std::cin >> bytes >> timeout) && bytes == 64 && timeout == 60);
  tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
  Observer sink;
  td::Bits256 zero;
  zero.set_zero();
  sink.expected = tos::create_serialize_tl_object<tos::tos_api::rldp_message>(
      zero, td::BufferSlice("churn"));
  auto encoder = td::fec::RaptorQEncoder::create(sink.expected.clone(), 768);
  encoder->prepare_more_symbols();
  tos::fec::FecType fec{encoder->get_parameters()};
  tos::rldp2::TransferId id;
  id.as_slice().fill(7);
  connection.send(id, td::BufferSlice(std::string(bytes, '*')),
                  td::Timestamp::in(timeout));
  connection.run(sink);
  connection.receive_raw(
      tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
          id, fec.tl(), 0, sink.expected.size(), 0,
          encoder->gen_symbol(0).data));
  connection.run(sink);
  CHECK(sink.delivered == 1 && sink.completed == 0 &&
        connection.outbound_transfer_count() == 1);
  connection.receive_raw(
      tos::create_serialize_tl_object<tos::tos_api::rldp2_complete>(id, 0));
  connection.run(sink);
  CHECK(sink.completed == 1 && connection.outbound_transfer_count() == 0 &&
        connection.completed_transfer_count() == 1);
  std::cout << "{\"delivered\":" << sink.delivered
            << ",\"outbound_pending_after_inbound\":true,\"ack_completed\":"
            << sink.completed
            << ",\"outbound_retained\":" << connection.outbound_transfer_count()
            << ",\"inbound_remembered\":"
            << connection.completed_transfer_count() << "}\n";
}
