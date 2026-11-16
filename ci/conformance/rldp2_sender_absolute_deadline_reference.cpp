#include "rldp2/RldpConnection.h"
#include <chrono>
#include <iostream>
#include <thread>
struct Sink : tos::rldp2::ConnectionCallback {
  unsigned packets{0}, expired{0};
  void send_raw(td::BufferSlice) override { ++packets; }
  void receive(tos::rldp2::TransferId, td::Result<td::BufferSlice>) override {
    UNREACHABLE();
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit> result) override {
    CHECK(result.is_error());
    ++expired;
  }
};
int main() {
  unsigned deadline_ms, loss_ms;
  while (std::cin >> deadline_ms >> loss_ms) {
    tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
    tos::rldp2::TransferId id;
    id.set_zero();
    Sink sink;
    connection.send(id, td::BufferSlice("query"),
                    td::Timestamp::in(deadline_ms / 1000.0));
    connection.run(sink);
    CHECK(sink.packets > 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(loss_ms));
    connection.run(sink);
    std::cout << "{\"deadline_ms\":" << deadline_ms
              << ",\"loss_ms\":" << loss_ms
              << ",\"pending\":" << connection.outbound_transfer_count()
              << ",\"expired\":" << sink.expired << "}\n";
  }
}
