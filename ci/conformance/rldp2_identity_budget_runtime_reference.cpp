// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
#include <memory>
#include <vector>
struct Sink : tos::rldp2::ConnectionCallback {
  void send_raw(td::BufferSlice) override {}
  void receive(tos::rldp2::TransferId, td::Result<td::BufferSlice>) override {
    UNREACHABLE();
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {
    UNREACHABLE();
  }
};
int main() {
  unsigned count, per_connection, bytes;
  CHECK(bool(std::cin >> count >> per_connection >> bytes));
  CHECK(count == 4 && per_connection == 256 && bytes == 2048);
  tos::rldp2::RldpPeerIdentity a{}, b{};
  b[0] = 1;
  auto budget = tos::rldp2::RldpInboundBudget::process_default();
  std::vector<std::unique_ptr<tos::rldp2::RldpConnection>> connections;
  for (unsigned i = 0; i <= count; ++i)
    connections.push_back(std::make_unique<tos::rldp2::RldpConnection>(a));
  auto other = std::make_unique<tos::rldp2::RldpConnection>(b);
  auto encoder = td::fec::RaptorQEncoder::create(
      td::BufferSlice(std::string(bytes, '*')), 768);
  encoder->prepare_more_symbols();
  tos::fec::FecType fec{encoder->get_parameters()};
  Sink sink;
  auto feed = [&](tos::rldp2::RldpConnection &connection, unsigned n) {
    td::Bits256 id;
    id.set_zero();
    id.as_slice()[0] = static_cast<char>(n & 255);
    id.as_slice()[1] = static_cast<char>(n >> 8);
    connection.receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            id, fec.tl(), 0, bytes, 0, encoder->gen_symbol(0).data));
    connection.run(sink);
  };
  for (unsigned i = 0; i < count; ++i) {
    for (unsigned n = 0; n < per_connection; ++n)
      feed(*connections[i], n);
    CHECK(connections[i]->inbound_transfer_count() == per_connection);
  }
  auto full_decoders = budget->identity_decoders(a);
  auto full_bytes = budget->identity_bytes(a);
  feed(*connections[4], 0);
  auto blocked = connections[4]->inbound_transfer_count();
  CHECK(blocked == 0);
  feed(*other, 0);
  auto independent = other->inbound_transfer_count();
  CHECK(independent == 1);
  // A still-owned native connection retains its allocations until destruction.
  feed(*connections[4], 0);
  auto held_blocked = connections[4]->inbound_transfer_count();
  auto held_decoders = budget->identity_decoders(a);
  auto held_bytes = budget->identity_bytes(a);
  feed(*other, 1);
  auto other_while_held = other->inbound_transfer_count();
  CHECK(held_blocked == 0 && held_decoders == 1024 && other_while_held == 2);
  connections[0].reset();
  auto after_eviction = budget->identity_decoders(a);
  auto bytes_after_eviction = budget->identity_bytes(a);
  feed(*connections[4], 0);
  auto retried = connections[4]->inbound_transfer_count();
  CHECK(retried == 1);
  auto after_retry = budget->identity_decoders(a);
  auto bytes_after_retry = budget->identity_bytes(a);
  CHECK(budget->identity_decoders(b) == 2);
  connections.clear();
  other.reset();
  CHECK(budget->identity_decoders(a) == 0 && budget->identity_bytes(a) == 0);
  CHECK(budget->identity_decoders(b) == 0 && budget->identity_bytes(b) == 0);
  std::cout << "{\"full_decoders\":" << full_decoders
            << ",\"full_bytes\":" << full_bytes
            << ",\"blocked_inbound\":" << blocked
            << ",\"other_inbound\":" << independent
            << ",\"held_decoders\":" << held_decoders
            << ",\"held_bytes\":" << held_bytes
            << ",\"held_blocked\":" << held_blocked
            << ",\"other_while_held\":" << other_while_held
            << ",\"after_eviction\":" << after_eviction
            << ",\"bytes_after_eviction\":" << bytes_after_eviction
            << ",\"retry_inbound\":" << retried
            << ",\"after_retry\":" << after_retry
            << ",\"bytes_after_retry\":" << bytes_after_retry
            << ",\"released_a_decoders\":0,\"released_a_bytes\":0,\"released_b_"
               "decoders\":0,\"released_b_bytes\":0}\n";
}
