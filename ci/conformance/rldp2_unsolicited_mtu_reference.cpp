// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
struct Sink : tos::rldp2::ConnectionCallback {
  unsigned errors{0}, deliveries{0}, completes{0};
  std::string payload_hash;
  void send_raw(td::BufferSlice bytes) override {
    auto obj = tos::fetch_tl_object<tos::tos_api::rldp2_MessagePart>(
        bytes.as_slice(), true);
    CHECK(obj.is_ok());
    if (obj.ok()->get_id() == tos::tos_api::rldp2_complete::ID)
      ++completes;
  }
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> result) override {
    if (result.is_error()) {
      ++errors;
      return;
    }
    auto message = tos::fetch_tl_object<tos::tos_api::rldp_message>(
        result.ok().as_slice(), true);
    CHECK(message.is_ok());
    ++deliveries;
    payload_hash = td::hex_encode(td::sha256(message.ok()->data_.as_slice()));
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {}
};
int main() {
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  std::string name;
  unsigned size;
  while (std::cin >> name >> size) {
    CHECK(size >= 4 && size <= 8000);
    tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
    tos::rldp2::TransferId id;
    id.set_zero();
    std::string payload(size, '*');
    payload.replace(0, 4, "mtu:");
    auto message = tos::create_serialize_tl_object<tos::tos_api::rldp_message>(
        id, td::BufferSlice(payload));
    unsigned wire_size = message.size();
    auto encoder = td::fec::RaptorQEncoder::create(std::move(message), 768);
    encoder->prepare_more_symbols();
    tos::fec::FecType fec{encoder->get_parameters()};
    Sink sink;
    std::string transcript;
    auto send = [&](unsigned seq) {
      auto packet =
          tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
              id, fec.tl(), 0, wire_size, seq, encoder->gen_symbol(seq).data);
      transcript.append(packet.as_slice().data(), packet.size());
      connection.receive_raw(std::move(packet));
      connection.run(sink);
    };
    for (unsigned seq = 0; seq < (wire_size + 767) / 768; ++seq)
      send(seq);
    send(0);
    std::cout << "{\"id\":\"" << name << "\",\"wire_size\":" << wire_size
              << ",\"active\":" << connection.inbound_transfer_count()
              << ",\"completed\":" << connection.completed_transfer_count()
              << ",\"errors\":" << sink.errors
              << ",\"deliveries\":" << sink.deliveries
              << ",\"complete_packets\":" << sink.completes
              << ",\"payload_sha256\":\"" << sink.payload_hash
              << "\",\"input_sha256\":\""
              << td::hex_encode(td::sha256(transcript)) << "\"}\n";
  }
}
