// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include <iostream>
int main() {
  unsigned first_count, second_count, bytes, timeout;
  CHECK(bool(std::cin >> first_count >> second_count >> bytes >> timeout));
  CHECK(first_count == 256 && second_count == 1 && bytes == 64 &&
        timeout == 60);
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();
  Harness h;
  auto first = std::make_shared<Held>();
  auto second = std::make_shared<Held>();
  h.subscribe(h.answerer_, "held",
              std::make_unique<AnnotatingSubscriber>(first));
  h.subscribe(h.buffered_, "held",
              std::make_unique<AnnotatingSubscriber>(second));
  for (unsigned i = 0; i < first_count; ++i) {
    auto result =
        std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
    h.query(h.answerer_, td::BufferSlice("held-query"), timeout, 1024, result);
  }
  h.wait_for([&] { return first->count() == first_count; },
             "first identity queries missing");
  h.requester_receives(false);
  h.run([&] {
    first->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for([&] { return h.outbound(h.answerer_).live == first_count; },
             "first identity did not fill");
  auto result = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
  h.query(h.buffered_, td::BufferSlice("held-second"), timeout, 1024, result);
  h.wait_for([&] { return second->count() == second_count; },
             "second identity query missing");
  h.run([&] {
    second->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for([&] { return h.outbound(h.buffered_).live == second_count; },
             "first identity starved second identity");
  require(h.outbound(h.answerer_).live == first_count,
          "first identity responses evicted");
  std::cout << "{\"first_live\":256,\"second_live\":1}\n";
}
