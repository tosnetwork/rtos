// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
#include <memory>
#include <vector>
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
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  std::string name;
  unsigned count, reverse, retire, solicited, tail_size;
  auto budget = tos::rldp2::RldpInboundBudget::process_default();
  while (std::cin >> name >> count >> reverse >> retire >> solicited >>
         tail_size) {
    CHECK(count >= 2 && count <= 3 && reverse <= 1 && retire <= 1 &&
          solicited <= 1);
    CHECK(budget->active_decoders() == 0 && budget->reserved_bytes() == 0 &&
          budget->tracked_identities() == 0);
    CHECK(tail_size == 772);
    unsigned total = (count - 1) * 2000000 + tail_size;
    tos::rldp2::RldpPeerIdentity peer{};
    auto connection = std::make_unique<tos::rldp2::RldpConnection>(peer);
    connection->set_default_mtu(16 << 20);
    tos::rldp2::TransferId id;
    id.set_zero();
    if (solicited)
      CHECK(connection->set_receive_limits(id, td::Timestamp::in(30), total));
    std::string payload(total - 40, '*');
    payload.replace(0, 4, "mtu:");
    auto message = tos::create_serialize_tl_object<tos::tos_api::rldp_message>(
        id, td::BufferSlice(payload));
    CHECK(message.size() == total);
    std::vector<std::unique_ptr<td::fec::RaptorQEncoder>> encoders;
    for (unsigned part = 0; part < count; ++part) {
      auto offset = part * 2000000;
      auto size = part + 1 == count ? tail_size : 2000000;
      encoders.push_back(td::fec::RaptorQEncoder::create(
          td::BufferSlice(message.as_slice().substr(offset, size)), 768));
      encoders.back()->prepare_more_symbols();
    }
    Sink sink;
    auto feed = [&](unsigned part, unsigned seq) {
      tos::fec::FecType fec{encoders[part]->get_parameters()};
      connection->receive_raw(
          tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
              id, fec.tl(), part, total, seq,
              encoders[part]->gen_symbol(seq).data));
      connection->run(sink);
    };
    auto snapshot = [&](const char *phase, unsigned part) {
      std::cout << "{\"id\":\"" << name << "\",\"phase\":\"" << phase
                << "\",\"part\":" << part
                << ",\"owner_live\":" << (connection ? "true" : "false")
                << ",\"inbound\":"
                << (connection
                        ? std::to_string(connection->inbound_transfer_count())
                        : "null")
                << ",\"decoders\":" << budget->active_decoders()
                << ",\"bytes\":" << budget->reserved_bytes()
                << ",\"unsolicited_bytes\":" << budget->unsolicited_bytes()
                << ",\"identity_bytes\":" << budget->identity_bytes(peer)
                << ",\"identities\":" << budget->tracked_identities()
                << ",\"deliveries\":" << sink.deliveries
                << ",\"payload_sha256\":\"" << sink.payload_hash << "\"}\n";
    };
    for (unsigned part = 0; part < count; ++part)
      feed(part, 0);
    snapshot("admitted", 0);
    for (unsigned i = 0; i < count; ++i) {
      auto part = reverse ? count - 1 - i : i;
      unsigned size = part + 1 == count ? tail_size : 2000000;
      for (unsigned seq = 1; seq < (size + 767) / 768; ++seq)
        feed(part, seq);
      snapshot("decoded", part);
      if (retire) {
        CHECK(sink.deliveries == 0);
        connection.reset();
        snapshot("retired", part);
        break;
      }
    }
    if (!retire) {
      CHECK(sink.deliveries == 1 &&
            sink.payload_hash == td::hex_encode(td::sha256(payload)));
      connection.reset();
      snapshot("shutdown", count - 1);
    }
    CHECK(budget->active_decoders() == 0 && budget->reserved_bytes() == 0 &&
          budget->tracked_identities() == 0);
  }
}
