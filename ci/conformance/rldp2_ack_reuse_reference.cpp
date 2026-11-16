// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
#include <optional>
struct Observer : tos::rldp2::ConnectionCallback {
  std::optional<tos::rldp2::TransferId> first;
  unsigned completed{0};
  void send_raw(td::BufferSlice packet) override {
    auto object = tos::fetch_tl_object<tos::tos_api::rldp2_MessagePart>(
        packet.as_slice(), true);
    CHECK(object.is_ok());
    if (object.ok()->get_id() == tos::tos_api::rldp2_messagePart::ID &&
        !first) {
      first = static_cast<tos::tos_api::rldp2_messagePart &>(*object.ok())
                  .transfer_id_;
    }
  }
  void receive(tos::rldp2::TransferId, td::Result<td::BufferSlice>) override {}
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit> result) override {
    if (result.is_ok())
      ++completed;
  }
};
int main() {
  unsigned count, bytes, timeout;
  CHECK(bool(std::cin >> count >> bytes >> timeout));
  CHECK(count == 257 && bytes == 64 && timeout == 60);
  tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
  auto id = [](unsigned value) {
    tos::rldp2::TransferId key;
    key.set_zero();
    key.as_slice().copy_from(
        td::Slice(reinterpret_cast<const char *>(&value), sizeof(value)));
    return key;
  };
  for (unsigned i = 0; i < count; ++i)
    connection.send(id(i), td::BufferSlice(std::string(bytes, '*')),
                    td::Timestamp::in(timeout));
  CHECK(connection.outbound_transfer_count() == 256);
  Observer observer;
  connection.run(observer);
  CHECK(observer.first.has_value());
  auto ack = [&] {
    connection.receive_raw(tos::serialize_tl_object(
        tos::create_tl_object<tos::tos_api::rldp2_complete>(*observer.first, 0),
        true));
    connection.run(observer);
  };
  ack();
  CHECK(connection.outbound_transfer_count() == 255 && observer.completed == 1);
  connection.send(id(count), td::BufferSlice(std::string(bytes, '*')),
                  td::Timestamp::in(timeout));
  CHECK(connection.outbound_transfer_count() == 256 &&
        connection.outbound_transfers_started() == 257);
  ack();
  CHECK(connection.outbound_transfer_count() == 256 && observer.completed == 1);
  std::cout
      << "{\"initial\":256,\"after_ack\":255,\"after_replacement\":256,"
         "\"started\":257,\"completed\":1,\"duplicate_ack_retained\":256}\n";
}
