// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include <ctime>
#include <iostream>

class ChurnObserver : public tos::adnl::Adnl::Callback {
public:
  explicit ChurnObserver(std::shared_ptr<std::atomic<unsigned>> count)
      : count_(std::move(count)) {}
  void receive_message(tos::adnl::AdnlNodeIdShort, tos::adnl::AdnlNodeIdShort,
                       td::BufferSlice data) override {
    CHECK(data.as_slice() == td::Slice("churn"));
    ++*count_;
  }

private:
  std::shared_ptr<std::atomic<unsigned>> count_;
};

int main() {
  unsigned count, original, replacement, timeout;
  CHECK(bool(std::cin >> count >> original >> replacement >> timeout));
  CHECK(count == 2048 && original == 64 && replacement == 65 && timeout == 60);
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  td::set_default_failure_signal_handler().ensure();
  Harness h;
  auto held = std::make_shared<Held>();
  auto delivered = std::make_shared<std::atomic<unsigned>>(0);
  td::Bits256 zero;
  zero.set_zero();
  auto query_data =
      tos::create_serialize_tl_object<tos::tos_api::overlay_query>(zero);
  h.subscribe(h.answerer_, query_data.as_slice().truncate(4).str(),
              std::make_unique<AnnotatingSubscriber>(held));
  h.subscribe(h.answerer_, "churn", std::make_unique<ChurnObserver>(delivered));
  // Establish both ADNL channel directions before dropping response traffic.
  // Cold no-channel traffic has its own limiter and cannot churn this cache.
  auto warmed = std::make_shared<std::atomic<unsigned>>(0);
  h.subscribe(h.requester_, "churn", std::make_unique<ChurnObserver>(warmed));
  h.run([&] {
    td::actor::send_closure(h.adnl_, &tos::adnl::Adnl::send_message,
                            h.requester_, h.answerer_,
                            td::BufferSlice("churn"));
  });
  h.wait_for([&] { return delivered->load() == 1; },
             "warm request not delivered");
  h.run([&] {
    td::actor::send_closure(h.adnl_, &tos::adnl::Adnl::send_message,
                            h.answerer_, h.requester_,
                            td::BufferSlice("churn"));
  });
  h.wait_for([&] { return warmed->load() == 1; }, "warm reply not delivered");
  h.run_for(0.2);
  delivered->store(0);
  h.requester_receives(false);
  auto feed = [&](td::Bits256 id, td::BufferSlice data) {
    auto encoder = td::fec::RaptorQEncoder::create(data.clone(), 768);
    encoder->prepare_more_symbols();
    tos::fec::FecType fec{encoder->get_parameters()};
    auto packet =
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            id, fec.tl(), 0, data.size(), 0, encoder->gen_symbol(0).data);
    h.run([&] {
      td::actor::send_closure(h.adnl_, &tos::adnl::Adnl::send_message,
                              h.requester_, h.answerer_, std::move(packet));
    });
  };
  td::Bits256 request_id, query_id;
  request_id.as_slice().fill(static_cast<char>(248));
  query_id.as_slice().fill(9);
  auto request = tos::create_serialize_tl_object<tos::tos_api::rldp_query>(
      query_id, 1024, static_cast<td::int32>(std::time(nullptr) + timeout),
      query_data.clone());
  auto started = td::Timestamp::now();
  feed(request_id, request.clone());
  h.wait_for([&] { return held->count() == 1; }, "initial query not delivered");
  h.run([&] {
    held->release(td::BufferSlice(std::string(original, '*')), td::Timestamp{});
  });
  h.wait_for([&] { return h.outbound(h.answerer_).started == 1; },
             "original response not started");
  auto before = h.outbound(h.answerer_);
  CHECK(before.live == 1);
  auto message = tos::create_serialize_tl_object<tos::tos_api::rldp_message>(
      zero, td::BufferSlice("churn"));
  for (unsigned i = 0; i < count; ++i) {
    td::Bits256 id;
    id.set_zero();
    id.as_slice().copy_from(
        td::Slice(reinterpret_cast<const char *>(&i), sizeof(i)));
    CHECK(td::Timestamp::now().at() - started.at() < 10);
    feed(id, message.clone());
    h.wait_for([&] { return delivered->load() == i + 1; },
               "cache churn message not delivered");
  }
  CHECK(td::Timestamp::now().at() - started.at() < 10);
  CHECK(h.outbound(h.answerer_).live == 1);
  feed(request_id, request.clone());
  h.wait_for([&] { return held->count() == 1; },
             "evicted query not delivered again");
  h.run([&] {
    held->release(td::BufferSlice(std::string(replacement, '*')),
                  td::Timestamp{});
  });
  // release() invokes its promise callback before outbound() queues its actor
  // stats request; the stats fan-out follows the response admission message.
  auto after = h.outbound(h.answerer_);
  CHECK(after.started == 1 && after.live == 1);
  size_t queries;
  {
    std::lock_guard lock(held->mutex);
    queries = held->queries.size();
  }
  CHECK(queries == 2);
  CHECK(td::Timestamp::now().at() - started.at() < 10);
  h.requester_receives(true);
  h.wait_for([&] { return h.outbound(h.answerer_).live == 0; },
             "original response not acknowledged", 5);
  std::cout << "{\"messages\":" << delivered->load()
            << ",\"queries\":" << queries
            << ",\"started_before\":" << before.started
            << ",\"started_after_replay\":" << after.started
            << ",\"retained_after_ack\":0}\n";
}
