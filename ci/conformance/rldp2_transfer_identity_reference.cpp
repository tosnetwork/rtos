// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <array>
#include <iostream>
struct Sink : tos::rldp2::ConnectionCallback {
  unsigned delivered{0};
  td::BufferSlice expected;
  void send_raw(td::BufferSlice) override {}
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> data) override {
    CHECK(data.is_ok() && data.ok().as_slice() == expected.as_slice());
    ++delivered;
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {}
};
int main() {
  unsigned count;
  CHECK(bool(std::cin >> count) && count == 3);
  td::Bits256 zero;
  zero.set_zero();
  auto message = tos::create_serialize_tl_object<tos::tos_api::rldp_message>(
      zero, td::BufferSlice("churn"));
  auto encoder = td::fec::RaptorQEncoder::create(message.clone(), 768);
  encoder->prepare_more_symbols();
  tos::fec::FecType fec{encoder->get_parameters()};
  auto symbol = encoder->gen_symbol(0).data;
  tos::rldp2::RldpConnection a{tos::rldp2::RldpPeerIdentity{}};
  tos::rldp2::RldpConnection b{tos::rldp2::RldpPeerIdentity{}};
  tos::rldp2::RldpConnection c{tos::rldp2::RldpPeerIdentity{}};
  tos::rldp2::RldpConnection *connections[] = {&a, &b, &c};
  Sink sink;
  sink.expected = message.clone();
  auto deliver = [&](tos::rldp2::RldpConnection &receiver) {
    receiver.receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            zero, fec.tl(), 0, message.size(), 0, symbol.clone()));
    receiver.run(sink);
  };
  for (auto *receiver : connections)
    deliver(*receiver);
  CHECK(sink.delivered == 3);
  for (auto *receiver : connections)
    deliver(*receiver);
  CHECK(sink.delivered == 3);
  CHECK(a.completed_transfer_count() == 1 &&
        b.completed_transfer_count() == 1 && c.completed_transfer_count() == 1);
  td::Bits256 send_id;
  send_id.as_slice().fill(7);
  for (auto *connection : connections) {
    connection->send(send_id, td::BufferSlice(std::string(64, '*')),
                     td::Timestamp::in(60));
    connection->run(sink);
    CHECK(connection->outbound_transfer_count() == 1);
  }
  std::array<std::array<unsigned, 3>, 3> pending;
  for (unsigned i = 0; i < 3; ++i) {
    for (unsigned duplicate = 0; duplicate < 2; ++duplicate) {
      connections[i]->receive_raw(
          tos::create_serialize_tl_object<tos::tos_api::rldp2_complete>(send_id,
                                                                        0));
      connections[i]->run(sink);
      for (unsigned j = 0; j < 3; ++j) {
        pending[i][j] = connections[j]->outbound_transfer_count();
        CHECK(pending[i][j] == (j > i ? 1 : 0));
      }
    }
  }
  std::cout << "{\"delivered\":" << sink.delivered
            << ",\"remembered\":[1,1,1],\"duplicates_suppressed\":true,\"ack_"
               "pending\":[";
  for (unsigned i = 0; i < 3; ++i) {
    if (i)
      std::cout << ",";
    std::cout << "[" << pending[i][0] << "," << pending[i][1] << ","
              << pending[i][2] << "]";
  }
  std::cout << "]}\n";
}
