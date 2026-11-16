#include "auto/tl/tos_api.hpp"
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include "tl-utils/tl-utils.hpp"
#include <iostream>
struct Sink : tos::rldp2::ConnectionCallback {
  unsigned complete{0}, received{0};
  void send_raw(td::BufferSlice bytes) override {
    auto obj = tos::fetch_tl_object<tos::tos_api::rldp2_MessagePart>(
        bytes.as_slice(), true);
    CHECK(obj.is_ok());
    if (obj.ok()->get_id() == tos::tos_api::rldp2_complete::ID)
      ++complete;
  }
  void receive(tos::rldp2::TransferId,
               td::Result<td::BufferSlice> data) override {
    CHECK(data.is_ok());
    ++received;
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {}
};
int main() {
  unsigned bytes;
  while (std::cin >> bytes) {
    CHECK(bytes > 0 && bytes <= 2048);
    tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
    auto encoder = td::fec::RaptorQEncoder::create(
        td::BufferSlice(std::string(bytes, '*')), 768);
    encoder->prepare_more_symbols();
    tos::fec::FecType fec{encoder->get_parameters()};
    tos::rldp2::TransferId id;
    id.set_zero();
    Sink sink;
    auto send = [&](unsigned symbol) {
      connection.receive_raw(
          tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
              id, fec.tl(), 0, bytes, symbol,
              encoder->gen_symbol(symbol).data));
      connection.run(sink);
    };
    for (unsigned symbol = 0; symbol < (bytes + 767) / 768; ++symbol)
      send(symbol);
    CHECK(sink.received == 1);
    const auto first = sink.complete;
    send(0);
    CHECK(sink.received == 1);
    std::cout << "{\"bytes\":" << bytes << ",\"first_complete\":" << first
              << ",\"duplicate_complete\":" << sink.complete - first
              << ",\"deliveries\":" << sink.received << "}\n";
  }
}
