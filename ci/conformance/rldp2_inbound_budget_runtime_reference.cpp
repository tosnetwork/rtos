// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
#include <memory>
struct Observer : tos::rldp2::ConnectionCallback {
  unsigned delivered{0};
  void send_raw(td::BufferSlice) override {}
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> data) override {
    CHECK(data.is_ok());
    ++delivered;
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {}
};
int main() {
  unsigned count, bytes;
  CHECK(bool(std::cin >> count >> bytes) && count == 257 && bytes == 2048);
  const tos::rldp2::RldpPeerIdentity peer{};
  auto budget = tos::rldp2::RldpInboundBudget::process_default();
  CHECK(budget->identity_decoders(peer) == 0 &&
        budget->identity_bytes(peer) == 0);
  auto owned = std::make_unique<tos::rldp2::RldpConnection>(peer);
  auto &connection = *owned;
  Observer sink;
  auto encoder = td::fec::RaptorQEncoder::create(
      td::BufferSlice(std::string(bytes, '*')), 768);
  encoder->prepare_more_symbols();
  tos::fec::FecType fec{encoder->get_parameters()};
  for (unsigned n = 0; n < count; ++n) {
    tos::rldp2::TransferId id;
    id.set_zero();
    id.as_slice()[0] = static_cast<char>(n & 255);
    id.as_slice()[1] = static_cast<char>(n >> 8);
    connection.receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            id, fec.tl(), 0, bytes, 0, encoder->gen_symbol(0).data));
    connection.run(sink);
  }
  CHECK(sink.delivered == 0);
  auto saturated = connection.inbound_transfer_count();
  auto bytes_cap = budget->identity_bytes(peer);
  CHECK(budget->identity_decoders(peer) == saturated);
  tos::rldp2::TransferId first;
  first.set_zero();
  for (unsigned symbol = 1; symbol < 3; ++symbol) {
    connection.receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            first, fec.tl(), 0, bytes, symbol,
            encoder->gen_symbol(symbol).data));
    connection.run(sink);
  }
  CHECK(sink.delivered == 1);
  auto after_completion = connection.inbound_transfer_count();
  auto bytes_completion = budget->identity_bytes(peer);
  CHECK(budget->identity_decoders(peer) == after_completion);
  tos::rldp2::TransferId retry;
  retry.set_zero();
  retry.as_slice()[1] = 1;
  connection.receive_raw(
      tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
          retry, fec.tl(), 0, bytes, 0, encoder->gen_symbol(0).data));
  connection.run(sink);
  auto after_retry = connection.inbound_transfer_count();
  auto bytes_retry = budget->identity_bytes(peer);
  CHECK(budget->identity_decoders(peer) == after_retry);
  tos::rldp2::TransferId answer;
  answer.as_slice().fill(77);
  CHECK(connection.set_receive_limits(answer, td::Timestamp::in(10), 1024));
  auto reply_encoder = td::fec::RaptorQEncoder::create(
      td::BufferSlice(std::string(64, '*')), 768);
  reply_encoder->prepare_more_symbols();
  tos::fec::FecType reply_fec{reply_encoder->get_parameters()};
  auto response = [&] {
    connection.receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            answer, reply_fec.tl(), 0, 64, 0,
            reply_encoder->gen_symbol(0).data));
    connection.run(sink);
  };
  response();
  auto solicited_blocked = sink.delivered == 1;
  first.as_slice()[0] = 1;
  for (unsigned symbol = 1; symbol < 3; ++symbol) {
    connection.receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            first, fec.tl(), 0, bytes, symbol,
            encoder->gen_symbol(symbol).data));
    connection.run(sink);
  }
  CHECK(sink.delivered == 2);
  response();
  CHECK(sink.delivered == 3);
  owned.reset();
  CHECK(budget->identity_decoders(peer) == 0 &&
        budget->identity_bytes(peer) == 0);
  std::cout << "{\"inbound\":" << saturated
            << ",\"after_completion\":" << after_completion
            << ",\"after_retry\":" << after_retry << ",\"solicited_blocked\":"
            << (solicited_blocked ? "true" : "false")
            << ",\"solicited_recovered\":true,\"bytes_at_cap\":" << bytes_cap
            << ",\"bytes_after_completion\":" << bytes_completion
            << ",\"bytes_after_retry\":" << bytes_retry
            << ",\"released_decoders\":0,\"released_bytes\":0}\n";
}
