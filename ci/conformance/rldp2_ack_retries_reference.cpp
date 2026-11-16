// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "rldp2/RldpReceiver.h"
#include "td/utils/overloaded.h"
#include <cmath>
#include <iostream>
int main() {
  using Receiver = tos::rldp2::RldpReceiver;
  Receiver receiver;
  std::string name, previous, op;
  int ms, seqno;
  unsigned step = 0;
  while (std::cin >> name >> op >> ms >> seqno) {
    if (name != previous) {
      receiver = Receiver{};
      previous = name;
      step = 0;
    }
    // Sample just after each nominal millisecond boundary. The increasing
    // nanosecond offset avoids equality depending on double addition order;
    // all recorded deadlines are rounded back to nominal milliseconds.
    auto now = td::Timestamp::at(100.0 + ms * 0.001 + (++step) * 1e-8);
    bool accepted = false, sent = false, ready = false;
    long long next = 0;
    if (op == "recv")
      accepted = receiver.on_received(seqno, now);
    else {
      CHECK(op == "poll");
      receiver.next_action(now).visit(
          td::overloaded([&](const Receiver::ActionSendAck &) { sent = true; },
                         [&](const Receiver::ActionWait &) {}));
      if (sent)
        receiver.on_ack_sent(now);
    }
    receiver.next_action(now).visit(td::overloaded(
        [&](const Receiver::ActionSendAck &) { ready = true; },
        [&](const Receiver::ActionWait &wait) {
          if (wait.wait_till)
            next = std::llround((wait.wait_till.at() - 100.0) * 1000.0);
        }));
    std::cout << "{\"case\":\"" << name << "\",\"op\":\"" << op
              << "\",\"ms\":" << ms
              << ",\"accepted\":" << (accepted ? "true" : "false")
              << ",\"sent\":" << (sent ? "true" : "false")
              << ",\"ready\":" << (ready ? "true" : "false")
              << ",\"next_ms\":" << next << "}\n";
  }
}
