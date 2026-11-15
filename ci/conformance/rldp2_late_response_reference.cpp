// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
// Reuse the pinned native fixture's production actor setup and diagnostics.
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include <iostream>

int main() {
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();
  unsigned timeout, bytes, limit, release_delay_ms, observe_ms;
  CHECK(bool(std::cin >> timeout >> bytes >> limit >> release_delay_ms >>
             observe_ms));
  CHECK(timeout == 10 && bytes == 64 && limit == 1024 &&
        release_delay_ms == 1100 && observe_ms == 500);
  Harness h;
  auto held = std::make_shared<Held>();
  h.subscribe(h.answerer_, "late",
              std::make_unique<AnnotatingSubscriber>(held));
  auto control = [&] {
    auto answer =
        std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
    h.query(h.answerer_, td::BufferSlice("late-control"), 10.0, 1024, answer);
    h.wait_for([&] { return held->count() == 1; },
               "control did not reach subscriber");
    h.run([&] {
      held->release(td::BufferSlice(std::string(64, '*')), td::Timestamp{});
    });
    h.wait_for([&] { return answer->has_value(); }, "control did not complete");
    require((*answer)->is_ok() &&
                (*answer)->ok().as_slice() == std::string(64, '*'),
            "control response differs");
    h.wait_for([&] { return h.outbound(h.answerer_).live == 0; },
               "control sender did not settle");
  };
  control();
  auto result = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
  h.query(h.answerer_, td::BufferSlice("late-query"), 10.0, 1024, result);
  h.wait_for([&] { return held->count() == 1; },
             "subscriber did not receive query");
  h.wait_for([&] { return result->has_value(); }, "query did not expire", 12.0);
  require((*result)->is_error() &&
              (*result)->error().code() == tos::ErrorCode::timeout,
          "held query did not return timeout");
  // Native wire time rounds the caller deadline up to the next second.
  h.run_for(1.1);
  const auto before = h.outbound(h.answerer_).started;
  h.run([&] {
    held->release(td::BufferSlice(std::string(64, '*')), td::Timestamp{});
  });
  h.run_for(0.5);
  const auto after = h.outbound(h.answerer_);
  require(after.started == before && after.live == 0,
          "expired query started a late response transfer");
  control();
  std::printf("{\"query_timeout_seconds\":10,\"late_response_started\":0,"
              "\"live\":0}\n");
}
