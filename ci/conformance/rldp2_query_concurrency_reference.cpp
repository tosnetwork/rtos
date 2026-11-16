// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include <iostream>

int main() {
  unsigned count, timeout, bytes, limit;
  CHECK(bool(std::cin >> count >> timeout >> bytes >> limit));
  CHECK(count == 256 && timeout == 10 && bytes == 64 && limit == 1024);
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  Harness h;
  auto held = std::make_shared<Held>();
  td::Bits256 zero;
  zero.set_zero();
  auto query =
      tos::create_serialize_tl_object<tos::tos_api::overlay_query>(zero);
  h.subscribe(h.answerer_, query.as_slice().truncate(4).str(),
              std::make_unique<AnnotatingSubscriber>(held));
  auto messages = std::make_shared<std::atomic<unsigned>>(0);
  class Messages : public tos::adnl::Adnl::Callback {
  public:
    explicit Messages(std::shared_ptr<std::atomic<unsigned>> count)
        : count_(std::move(count)) {}
    void receive_message(tos::adnl::AdnlNodeIdShort, tos::adnl::AdnlNodeIdShort,
                         td::BufferSlice data) override {
      CHECK(data.as_slice() == "churn");
      ++*count_;
    }
    void receive_query(tos::adnl::AdnlNodeIdShort, tos::adnl::AdnlNodeIdShort,
                       td::BufferSlice, td::Promise<td::BufferSlice>) override {
      UNREACHABLE();
    }

  private:
    std::shared_ptr<std::atomic<unsigned>> count_;
  };
  h.subscribe(h.answerer_, "chur", std::make_unique<Messages>(messages));
  struct Outcome {
    std::optional<td::Result<td::BufferSlice>> value;
    std::atomic<bool> ready{false};
  };
  using Answer = std::shared_ptr<Outcome>;
  auto send_query = [&](Answer answer) {
    h.run([&] {
      td::actor::send_closure(
          h.rldp_, &tos::rldp2::Rldp::send_query_ex, h.requester_, h.answerer_,
          std::string("concurrency"),
          td::PromiseCreator::lambda(
              [answer](td::Result<td::BufferSlice> result) {
                answer->value = std::move(result);
                answer->ready.store(true, std::memory_order_release);
              }),
          td::Timestamp::in(timeout), query.clone(), limit);
    });
  };
  std::vector<Answer> answers;
  for (unsigned i = 0; i < count; ++i) {
    auto answer = std::make_shared<Outcome>();
    send_query(answer);
    answers.push_back(answer);
  }
  h.wait_for([&] { return held->count() == count; },
             "all queries must reach the application while replies are held",
             2.0);
  auto stats = [&] {
    std::optional<tos::rldp2::Rldp::ConnectionStats> result;
    std::atomic<bool> ready{false};
    h.run([&] {
      td::actor::send_closure(
          h.rldp_, &tos::rldp2::Rldp::get_connection_stats,
          [&](td::Result<tos::rldp2::Rldp::ConnectionStats> value) {
            result = value.move_as_ok();
            ready.store(true, std::memory_order_release);
          });
    });
    h.wait_for([&] { return ready.load(std::memory_order_acquire); },
               "stats missing");
    return result->pending_queries;
  };
  CHECK(stats() == count);
  for (const auto &answer : answers)
    CHECK(!answer->ready.load(std::memory_order_acquire));
  auto extra = std::make_shared<Outcome>();
  send_query(extra);
  h.wait_for([&] { return extra->ready.load(std::memory_order_acquire); },
             "extra query must be refused");
  CHECK(extra->value->is_error() && extra->value->error().message().str().find(
                                        "from this peer") != std::string::npos);
  h.run([&] {
    td::actor::send_closure(h.rldp_, &tos::rldp2::Rldp::send_message,
                            h.requester_, h.answerer_,
                            td::BufferSlice("churn"));
  });
  h.wait_for([&] { return messages->load(std::memory_order_acquire) == 1; },
             "held queries must not block a message", 2.0);
  CHECK(held->count() == count);
  h.run([&] {
    held->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for(
      [&] {
        for (const auto &answer : answers)
          if (!answer->ready.load(std::memory_order_acquire))
            return false;
        return true;
      },
      "answers missing");
  for (const auto &answer : answers)
    CHECK(answer->value->is_ok() &&
          answer->value->ok().as_slice() == std::string(bytes, '*'));
  auto fresh = std::make_shared<Outcome>();
  send_query(fresh);
  h.wait_for([&] { return held->count() == 1; }, "fresh query missing");
  h.run([&] {
    held->release(td::BufferSlice(std::string(bytes, '*')), td::Timestamp{});
  });
  h.wait_for([&] { return fresh->ready.load(std::memory_order_acquire); },
             "fresh answer missing");
  CHECK(fresh->value->is_ok() &&
        fresh->value->ok().as_slice() == std::string(bytes, '*'));
  CHECK(stats() == 0);
  std::cout
      << "{\"held\":256,\"pending\":256,\"extra_refused\":true,\"messages\":1,"
         "\"answers\":256,\"recovery_bytes\":64,\"pending_end\":0}\n";
}
