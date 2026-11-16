// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include <chrono>
#include <iostream>
int main() {
  unsigned count, retained_timeout, query_timeout, bytes, limit;
  CHECK(bool(std::cin >> count >> retained_timeout >> query_timeout >> bytes >>
             limit));
  CHECK(count == 256 && retained_timeout == 60 && query_timeout == 10 &&
        bytes == 64 && limit == 1024);
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();
  Harness h;
  td::Bits256 overlay;
  overlay.set_zero();
  auto request = tos::serialize_tl_object(
      tos::create_tl_object<tos::tos_api::overlay_query>(overlay), true);
  auto forward = std::make_shared<Held>();
  auto reverse = std::make_shared<Held>();
  h.subscribe(h.answerer_, request.as_slice().truncate(4).str(),
              std::make_unique<AnnotatingSubscriber>(forward));
  h.subscribe(h.requester_, request.as_slice().truncate(4).str(),
              std::make_unique<AnnotatingSubscriber>(reverse));
  for (unsigned i = 0; i < count; ++i) {
    auto result =
        std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
    h.query(h.answerer_, request.clone(), retained_timeout, limit, result);
  }
  h.wait_for([&] { return forward->count() == count; },
             "requests did not reach subscriber");
  h.requester_receives(false);
  h.run([&] {
    forward->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for([&] { return h.outbound(h.answerer_).live == count; },
             "responses did not fill send slots");
  auto send_reverse =
      [&](std::shared_ptr<std::optional<td::Result<td::BufferSlice>>> result) {
        h.run([&] {
          td::actor::send_closure(
              h.rldp_, &tos::rldp2::Rldp::send_query_ex, h.answerer_,
              h.requester_, std::string("reverse"),
              [result](td::Result<td::BufferSlice> value) {
                *result = std::move(value);
              },
              td::Timestamp::in(query_timeout), request.clone(), limit);
        });
      };
  auto refused = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
  const auto start = std::chrono::steady_clock::now();
  send_reverse(refused);
  h.run_for(0.2);
  CHECK(!refused->has_value() && reverse->count() == 0);
  CHECK(h.outbound(h.answerer_).started == count);
  h.requester_receives(true);
  h.wait_for([&] { return h.outbound(h.answerer_).live == 0; },
             "response slots did not drain", 5.0);
  CHECK(!refused->has_value());
  h.wait_for([&] { return refused->has_value(); },
             "refused query missed original deadline", 12.0);
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now() - start)
                     .count();
  CHECK((*refused)->is_error() &&
        (*refused)->error().code() == tos::ErrorCode::timeout);
  CHECK(elapsed >= 9500 && elapsed < 13000);
  CHECK(reverse->count() == 0 && h.outbound(h.answerer_).started == count);
  auto fresh = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
  send_reverse(fresh);
  h.wait_for([&] { return reverse->count() == 1; },
             "fresh query did not reach peer");
  h.run([&] {
    reverse->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for([&] { return fresh->has_value(); }, "fresh query did not recover");
  CHECK((*fresh)->is_ok() &&
        (*fresh)->ok().as_slice() == std::string(bytes, '*'));
  std::cout
      << "{\"saturated\":256,\"drained_before_deadline\":true,\"timeout\":true,"
         "\"implicit_retry\":false,\"fresh_answer_bytes\":64,\"elapsed_ms\":"
      << elapsed << "}\n";
}
