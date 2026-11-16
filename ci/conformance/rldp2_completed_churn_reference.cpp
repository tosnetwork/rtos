// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
struct Sink : tos::rldp2::ConnectionCallback {
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
  unsigned count;
  CHECK(bool(std::cin >> count) && count == 2049);
  td::Bits256 zero;
  zero.set_zero();
  auto message = tos::create_serialize_tl_object<tos::tos_api::rldp_message>(
      zero, td::BufferSlice("churn"));
  auto encoder = td::fec::RaptorQEncoder::create(message.clone(), 768);
  encoder->prepare_more_symbols();
  tos::fec::FecType fec{encoder->get_parameters()};
  auto symbol = encoder->gen_symbol(0).data;
  tos::rldp2::RldpConnection receiver{tos::rldp2::RldpPeerIdentity{}};
  Sink sink;
  auto deliver = [&](unsigned value) {
    td::Bits256 id;
    id.set_zero();
    id.as_slice().copy_from(
        td::Slice(reinterpret_cast<const char *>(&value), sizeof(value)));
    receiver.receive_raw(
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            id, fec.tl(), 0, message.size(), 0, symbol.clone()));
    receiver.run(sink);
  };
  for (unsigned i = 0; i < count; ++i)
    deliver(i);
  CHECK(sink.delivered == count);
  auto remembered = receiver.completed_transfer_count();
  CHECK(remembered == 2048);
  deliver(0);
  CHECK(sink.delivered == count + 1);
  deliver(count - 1);
  CHECK(sink.delivered == count + 1);
  std::cout
      << "{\"unique_delivered\":2049,\"remembered\":" << remembered
      << ",\"oldest_replayed\":true,\"recent_suppressed\":true,\"delivered\":"
      << sink.delivered << "}\n";
}
