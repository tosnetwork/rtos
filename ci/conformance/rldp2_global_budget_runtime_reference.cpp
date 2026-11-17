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
  unsigned identities, per_identity, per_connection, bytes;
  CHECK(
      bool(std::cin >> identities >> per_identity >> per_connection >> bytes));
  CHECK(identities == 8 && per_identity == 4 && per_connection == 256 &&
        bytes == 2048);
  auto budget = tos::rldp2::RldpInboundBudget::process_default();
  std::vector<std::unique_ptr<tos::rldp2::RldpConnection>> unsolicited,
      solicited;
  for (unsigned i = 0; i < identities; ++i) {
    tos::rldp2::RldpPeerIdentity identity{};
    identity[0] = static_cast<unsigned char>(i);
    for (unsigned j = 0; j < per_identity; ++j) {
      unsolicited.push_back(
          std::make_unique<tos::rldp2::RldpConnection>(identity));
      tos::rldp2::RldpPeerIdentity reverse_identity{};
      reverse_identity[0] = static_cast<unsigned char>(64 + j);
      solicited.push_back(
          std::make_unique<tos::rldp2::RldpConnection>(reverse_identity));
    }
  }
  tos::rldp2::RldpPeerIdentity other{};
  other[0] = 99;
  auto probe = std::make_unique<tos::rldp2::RldpConnection>(other);
  auto encoder = td::fec::RaptorQEncoder::create(
      td::BufferSlice(std::string(bytes, '*')), 768);
  encoder->prepare_more_symbols();
  tos::fec::FecType fec{encoder->get_parameters()};
  Sink sink;
  auto feed = [&](tos::rldp2::RldpConnection &connection, unsigned n,
                  bool is_solicited) {
    td::Bits256 id;
    id.set_zero();
    id.as_slice()[0] = static_cast<char>(n & 255);
    id.as_slice()[1] = static_cast<char>(n >> 8);
    if (is_solicited)
      CHECK(connection.set_receive_limits(id, td::Timestamp::in(60), bytes));
    connection.receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            id, fec.tl(), 0, bytes, 0, encoder->gen_symbol(0).data));
    connection.run(sink);
  };
  for (auto &connection : unsolicited) {
    for (unsigned n = 0; n < per_connection; ++n)
      feed(*connection, n, false);
    CHECK(connection->inbound_transfer_count() == per_connection);
  }
  auto unsol_full = budget->unsolicited_decoders();
  feed(*probe, 0, false);
  auto unsol_blocked = probe->inbound_transfer_count();
  CHECK(unsol_blocked == 0);
  for (auto &connection : solicited) {
    for (unsigned n = 0; n < per_connection; ++n)
      feed(*connection, n, true);
    CHECK(connection->inbound_transfer_count() == per_connection);
  }
  auto full = budget->active_decoders();
  auto full_bytes = budget->reserved_bytes();
  feed(*probe, 1, true);
  auto total_blocked = probe->inbound_transfer_count();
  CHECK(total_blocked == 0);
  unsolicited[0].reset();
  auto evicted = budget->active_decoders();
  auto unsol_evicted = budget->unsolicited_decoders();
  feed(*probe, 1,
       false); // The refused packet retained its registered receive limit.
  CHECK(probe->inbound_transfer_count() == 1);
  feed(*probe, 0, false);
  CHECK(probe->inbound_transfer_count() == 2);
  auto retry = budget->active_decoders();
  auto unsol_retry = budget->unsolicited_decoders();
  unsolicited.clear();
  solicited.clear();
  probe.reset();
  CHECK(budget->active_decoders() == 0 && budget->reserved_bytes() == 0 &&
        budget->tracked_identities() == 0);
  std::cout << "{\"unsolicited_full\":" << unsol_full
            << ",\"unsolicited_blocked\":" << unsol_blocked
            << ",\"full_decoders\":" << full << ",\"full_bytes\":" << full_bytes
            << ",\"total_blocked\":" << total_blocked
            << ",\"after_eviction\":" << evicted
            << ",\"unsolicited_after_eviction\":" << unsol_evicted
            << ",\"after_retry\":" << retry
            << ",\"unsolicited_after_retry\":" << unsol_retry
            << ",\"released_decoders\":0,\"released_bytes\":0,\"released_"
               "identities\":0}\n";
}
