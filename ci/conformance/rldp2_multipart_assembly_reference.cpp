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
  size_t size{0};
  std::string digest;
  void send_raw(td::BufferSlice bytes) override {
    auto obj = tos::fetch_tl_object<tos::tos_api::rldp2_MessagePart>(
        bytes.as_slice(), true);
    CHECK(obj.is_ok());
    if (obj.ok()->get_id() == tos::tos_api::rldp2_complete::ID)
      ++completes;
  }
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> value) override {
    if (value.is_error()) {
      ++errors;
      return;
    }
    ++deliveries;
    size = value.ok().size();
    digest = td::hex_encode(td::sha256(value.ok().as_slice()));
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {}
};
int main() {
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  std::string name;
  unsigned count, reverse;
  while (std::cin >> name >> count >> reverse) {
    CHECK(count >= 2 && count <= 3 && reverse <= 1);
    const unsigned total = (count - 1) * 2000000 + 769;
    tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
    tos::rldp2::TransferId id;
    id.set_zero();
    CHECK(connection.set_receive_limits(id, td::Timestamp::in(30), total));
    Sink sink;
    std::vector<std::unique_ptr<td::fec::RaptorQEncoder>> encoders;
    for (unsigned part = 0; part < count; ++part) {
      std::string data(part + 1 == count ? 769 : 2000000, '\0');
      for (size_t i = 0; i < data.size(); ++i)
        data[i] = char((i * 17 + part * 29) % 251);
      encoders.push_back(
          td::fec::RaptorQEncoder::create(td::BufferSlice(data), 768));
      encoders.back()->prepare_more_symbols();
    }
    std::string transcript;
    auto send = [&](unsigned part, unsigned seq) {
      tos::fec::FecType fec{encoders[part]->get_parameters()};
      auto packet =
          tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
              id, fec.tl(), part, total, seq,
              encoders[part]->gen_symbol(seq).data);
      transcript.append(packet.as_slice().data(), packet.size());
      connection.receive_raw(std::move(packet));
      connection.run(sink);
    };
    auto snapshot = [&](std::string phase, unsigned part) {
      std::cout << "{\"id\":\"" << name << "\",\"phase\":\"" << phase
                << "\",\"part\":" << part
                << ",\"active\":" << connection.inbound_transfer_count()
                << ",\"completed\":" << connection.completed_transfer_count()
                << ",\"errors\":" << sink.errors
                << ",\"deliveries\":" << sink.deliveries
                << ",\"complete_packets\":" << sink.completes
                << ",\"size\":" << sink.size << ",\"sha256\":\"" << sink.digest
                << "\",\"input_sha256\":\""
                << td::hex_encode(td::sha256(transcript)) << "\"}\n";
    };
    for (unsigned part = 0; part < count; ++part)
      send(part, 0);
    snapshot("admitted", 0);
    for (unsigned i = 0; i < count; ++i) {
      unsigned part = reverse ? count - 1 - i : i;
      unsigned size = part + 1 == count ? 769 : 2000000;
      for (unsigned seq = 1; seq < (size + 767) / 768; ++seq)
        send(part, seq);
      snapshot("decoded", part);
    }
    for (unsigned part = 0; part < count; ++part) {
      send(part, 0);
      snapshot("replay", part);
    }
  }
}
