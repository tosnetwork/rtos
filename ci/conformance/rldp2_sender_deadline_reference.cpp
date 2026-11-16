// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include <iostream>

int main() {
  unsigned timeout, bytes, limit, observe_ms, expiry_ms;
  CHECK(bool(std::cin >> timeout >> bytes >> limit >> observe_ms >> expiry_ms));
  CHECK(timeout == 10 && bytes == 64 && limit == 1024 && observe_ms == 2000 &&
        expiry_ms == 13000);
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();
  Harness h;
  auto held = std::make_shared<Held>();
  h.subscribe(h.answerer_, "held",
              std::make_unique<AnnotatingSubscriber>(held));
  h.requester_receives(false);
  auto result = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
  auto sent = td::Timestamp::now();
  h.query(h.answerer_, td::BufferSlice("held-query"), timeout, limit, result);
  h.wait_for([&] { return held->count() == 1; },
             "subscriber did not receive query");
  h.run([&] {
    held->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for([&] { return h.outbound(h.answerer_).started == 1; },
             "response did not start");
  h.run_for(observe_ms / 1000.0);
  require(h.outbound(h.answerer_).live == 1,
          "unacknowledged response ended before query deadline");
  h.run_until(td::Timestamp::at(sent.at() + expiry_ms / 1000.0));
  require(h.outbound(h.answerer_).live == 0,
          "response survived query deadline");
  require(result->has_value() && (*result)->is_error() &&
              (*result)->error().code() == tos::ErrorCode::timeout,
          "caller did not time out");
  h.requester_receives(true);
  auto recovery =
      std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
  h.query(h.answerer_, td::BufferSlice("held-recovery"), timeout, limit,
          recovery);
  h.wait_for([&] { return held->count() == 1; },
             "recovery did not reach subscriber");
  h.run([&] {
    held->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for([&] { return recovery->has_value(); },
             "recovery did not complete");
  require((*recovery)->is_ok() &&
              (*recovery)->ok().as_slice() == std::string(bytes, '*'),
          "recovery response differs");
  std::printf("{\"held_before_deadline\":true,\"live_after_deadline\":0,"
              "\"recovery\":true}\n");
}
