#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <chrono>
#include <iostream>
#include <thread>
struct Sink : tos::rldp2::ConnectionCallback {
  unsigned complete{0}, received{0}, confirms{0}, completed_parts{0};
  void send_raw(td::BufferSlice bytes) override {
    auto obj = tos::fetch_tl_object<tos::tos_api::rldp2_MessagePart>(
        bytes.as_slice(), true);
    CHECK(obj.is_ok());
    if (obj.ok()->get_id() == tos::tos_api::rldp2_complete::ID)
      ++complete;
    if (obj.ok()->get_id() == tos::tos_api::rldp2_confirm::ID)
      ++confirms;
  }
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> data) override {
    CHECK(data.is_ok());
    ++received;
  }
  void on_part_completed(tos::rldp2::TransferId, td::uint32,
                         td::uint64) override {
    ++completed_parts;
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {}
};
int main() {
  unsigned bytes;
  while (std::cin >> bytes) {
    CHECK(bytes > 0 && bytes == 2000000);
    tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
    auto encoder = td::fec::RaptorQEncoder::create(
        td::BufferSlice(std::string(bytes, '*')), 768);
    encoder->prepare_more_symbols();
    tos::fec::FecType fec{encoder->get_parameters()};
    tos::rldp2::TransferId id;
    id.set_zero();
    CHECK(connection.set_receive_limits(id, td::Timestamp::in(10), bytes + 1));
    Sink sink;
    auto send = [&](unsigned symbol) {
      connection.receive_raw(
          tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
              id, fec.tl(), 0, bytes + 1, symbol,
              encoder->gen_symbol(symbol).data));
    };
    for (unsigned symbol = 0; symbol < (bytes + 767) / 768; ++symbol)
      send(symbol);
    connection.run(sink);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    connection.run(sink);
    CHECK(sink.received == 0);
    CHECK(sink.completed_parts == 1);
    CHECK(connection.inbound_transfer_count() == 1);
    const auto first = sink.complete;
    send(0);
    connection.run(sink);
    CHECK(sink.received == 0);
    std::cout << "{\"bytes\":" << bytes << ",\"first_complete\":" << first
              << ",\"duplicate_complete\":" << sink.complete - first
              << ",\"confirm_packets\":" << sink.confirms
              << ",\"deliveries\":" << sink.received << "}\n";
  }
}
