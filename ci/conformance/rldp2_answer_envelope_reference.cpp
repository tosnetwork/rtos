// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include <iostream>

int main() {
  unsigned fill, bytes, limit;
  CHECK(bool(std::cin >> fill >> bytes >> limit));
  CHECK(fill == 0 && bytes == 64 && limit == 1024);
  SET_VERBOSITY_LEVEL(verbosity_ERROR);
  Harness h;
  auto held = std::make_shared<Held>();
  h.subscribe(h.answerer_, "held",
              std::make_unique<AnnotatingSubscriber>(held));
  auto result = std::make_shared<std::optional<td::Result<td::BufferSlice>>>();
  td::Bits256 request;
  request.as_slice().fill(7);
  h.run([&] {
    td::actor::send_closure(
        h.rldp_, &tos::rldp2::Rldp::send_query_ex_with_transfer_id,
        h.requester_, h.answerer_, std::string("answer-envelope"),
        td::PromiseCreator::lambda(
            [result](td::Result<td::BufferSlice> answer) {
              *result = std::move(answer);
            }),
        td::Timestamp::in(10), td::BufferSlice("held-query"), limit, request);
  });
  h.wait_for([&] { return held->count() == 1; }, "query must reach subscriber");
  auto inject = [&](unsigned transfer_fill) {
    td::Bits256 query_id, transfer_id;
    query_id.as_slice().fill(fill);
    transfer_id.as_slice().fill(transfer_fill);
    auto answer = tos::create_serialize_tl_object<tos::tos_api::rldp_answer>(
        query_id, td::BufferSlice(std::string(bytes, '*')));
    auto size = answer.size();
    auto encoder = td::fec::RaptorQEncoder::create(std::move(answer), 768);
    encoder->prepare_more_symbols();
    tos::fec::FecType fec{encoder->get_parameters()};
    auto packet =
        tos::create_serialize_tl_object<tos::tos_api::rldp2_messagePart>(
            transfer_id, fec.tl(), 0, size, 0, encoder->gen_symbol(0).data);
    h.run([&] {
      td::actor::send_closure(h.adnl_, &tos::adnl::Adnl::send_message,
                              h.answerer_, h.requester_, std::move(packet));
    });
  };
  inject(247);
  h.run_for(0.1);
  CHECK(!result->has_value());
  inject(248);
  h.wait_for([&] { return result->has_value(); },
             "response did not settle query");
  CHECK((*result)->is_ok());
  CHECK((*result)->ok().as_slice() == std::string(bytes, '*'));
  std::cout << "{\"wrong_transfer_pending\":true,\"answer_bytes\":64,\"answer_"
               "fill\":42}\n";
}
