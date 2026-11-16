// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
#include <memory>
struct Sink : tos::rldp2::ConnectionCallback {
  unsigned deliveries{0};
  std::string payload_hash;
  void send_raw(td::BufferSlice) override {}
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> result) override {
    CHECK(result.is_ok());
    auto message = tos::fetch_tl_object<tos::tos_api::rldp_message>(
        result.ok().as_slice(), true);
    CHECK(message.is_ok());
    ++deliveries;
    payload_hash = td::hex_encode(td::sha256(message.ok()->data_.as_slice()));
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {
    UNREACHABLE();
  }
};
int main() {
  unsigned bytes, pressure_count;
  CHECK(bool(std::cin >> bytes >> pressure_count));
  CHECK(bytes == 1048576 && pressure_count == 30);
  auto budget = tos::rldp2::RldpInboundBudget::process_default();
  std::unique_ptr<tos::rldp2::RldpConnection> connections[5];
  for (unsigned i = 0; i < 5; ++i) {
    tos::rldp2::RldpPeerIdentity peer{};
    peer[0] = static_cast<unsigned char>(i + 1);
    connections[i] = std::make_unique<tos::rldp2::RldpConnection>(peer);
    connections[i]->set_default_mtu(16 << 20);
  }
  td::Bits256 message_id;
  message_id.set_zero();
  std::string payload(bytes - 40, '*');
  payload.replace(0, 4, "mtu:");
  auto message = tos::create_serialize_tl_object<tos::tos_api::rldp_message>(
      message_id, td::BufferSlice(payload));
  CHECK(message.size() == bytes);
  auto large = td::fec::RaptorQEncoder::create(std::move(message), 768);
  auto small = td::fec::RaptorQEncoder::create(
      td::BufferSlice(std::string(2048, '*')), 768);
  large->prepare_more_symbols();
  small->prepare_more_symbols();
  tos::fec::FecType large_fec{large->get_parameters()},
      small_fec{small->get_parameters()};
  Sink sink;
  auto feed = [&](unsigned connection, unsigned n, unsigned seq, bool solicited,
                  bool little = false) {
    td::Bits256 id;
    id.set_zero();
    id.as_slice()[0] = static_cast<char>(n & 255);
    id.as_slice()[1] = static_cast<char>(n >> 8);
    auto size = little ? 2048 : bytes;
    if (solicited)
      CHECK(connections[connection]->set_receive_limits(
          id, td::Timestamp::in(60), size));
    auto &encoder = little ? small : large;
    auto &fec = little ? small_fec : large_fec;
    connections[connection]->receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            id, fec.tl(), 0, size, seq, encoder->gen_symbol(seq).data));
    connections[connection]->run(sink);
    return connections[connection]->inbound_transfer_count();
  };
  auto fill = [&](unsigned connection, bool solicited) {
    for (unsigned n = 0; n < 256; ++n) {
      auto count = feed(connection, n, 0, solicited);
      if (count == n)
        return n;
      CHECK(count == n + 1);
    }
    UNREACHABLE();
  };
  auto a = fill(0, false), b = fill(1, false), c = fill(2, false),
       d = fill(3, true);
  CHECK(a == 36 && b == 36 && c == 2 && d == 77);
  auto full_bytes = budget->reserved_bytes();
  for (unsigned n = 0; n < pressure_count; ++n)
    CHECK(feed(4, n, 0, true, true) == n + 1);
  auto pressure_bytes = budget->reserved_bytes();
  auto symbols = large_fec.symbols_count();
  for (unsigned seq = 1; seq < symbols; ++seq)
    feed(0, 0, seq, false);
  CHECK(sink.deliveries == 0 && connections[0]->inbound_transfer_count() == a);
  auto blocked_decoders = budget->active_decoders();
  connections[4].reset();
  auto released_solver_bytes = budget->reserved_bytes();
  feed(0, 0, symbols, false);
  CHECK(sink.deliveries == 1 &&
        sink.payload_hash == td::hex_encode(td::sha256(payload)));
  auto decoded_bytes = budget->reserved_bytes();
  CHECK(feed(0, a, 0, false) == a);
  connections[1].reset();
  auto evicted = budget->active_decoders();
  CHECK(feed(2, c, 0, false) == c + 1);
  CHECK(feed(3, d, 0, false) ==
        d + 1); // The refused solicited receive limit is retained.
  auto retry = budget->active_decoders(),
       unsolicited_retry = budget->unsolicited_decoders();
  for (auto &connection : connections)
    connection.reset();
  CHECK(budget->active_decoders() == 0 && budget->reserved_bytes() == 0 &&
        budget->tracked_identities() == 0);
  std::cout << "{\"identity_a\":" << a << ",\"identity_b\":" << b
            << ",\"pool_tail\":" << c << ",\"solicited_tail\":" << d
            << ",\"full_bytes\":" << full_bytes
            << ",\"solver_pressure_bytes\":" << pressure_bytes
            << ",\"blocked_decoders\":" << blocked_decoders
            << ",\"blocked_deliveries\":0,\"after_solver_release_bytes\":"
            << released_solver_bytes
            << ",\"after_decode_bytes\":" << decoded_bytes
            << ",\"deliveries\":" << sink.deliveries << ",\"payload_sha256\":\""
            << sink.payload_hash << "\",\"after_eviction\":" << evicted
            << ",\"after_retry\":" << retry
            << ",\"unsolicited_after_retry\":" << unsolicited_retry
            << ",\"released_decoders\":0,\"released_bytes\":0,\"released_"
               "identities\":0}\n";
}
