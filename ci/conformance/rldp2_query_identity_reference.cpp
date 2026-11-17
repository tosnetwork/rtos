// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#define main original_lifetime_fixture_main
#include "test/test-rldp2-refusal-lifetime.cpp"
#undef main
#include "rldp2/RldpConnection.h"
#include "td/fec/raptorq/Encoder.h"
#include <array>
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
  // Every tested identity has a direct authenticated loopback route.
  std::array<tos::adnl::AdnlNodeIdShort, 3> ids{h.requester_, h.answerer_,
                                                h.buffered_};
  for (auto dst : ids) {
    std::optional<tos::PublicKey> pub;
    h.run([&] {
      td::actor::send_closure(
          h.keyring_, &tos::keyring::Keyring::get_public_key, dst.pubkey_hash(),
          [&](td::Result<tos::PublicKey> value) { pub = value.move_as_ok(); });
    });
    h.wait_for([&] { return pub.has_value(); }, "identity key unavailable");
    for (auto src : ids) {
      if (src == dst)
        continue;
      h.run([&] {
        td::actor::send_closure(
            h.adnl_, &tos::adnl::Adnl::add_peer, src,
            tos::adnl::AdnlNodeIdFull{*pub},
            tos::adnl::TestLoopbackNetworkManager::generate_dummy_addr_list());
      });
    }
  }
  auto decoded = std::make_shared<std::array<unsigned, 3>>();
  h.run([&] {
    td::actor::send_closure(
        h.rldp_, &tos::rldp2::Rldp::set_part_completed_callback,
        [decoded, requester = h.requester_, answerer = h.answerer_,
         other = h.buffered_](tos::adnl::AdnlNodeIdShort local,
                              tos::adnl::AdnlNodeIdShort peer, td::Bits256 id,
                              td::uint32 part, td::uint64 bytes) {
          td::Bits256 response;
          response.as_slice().fill(248);
          if (id != response)
            return;
          CHECK(part == 0 && bytes > 64);
          if (local == requester && peer == other)
            ++(*decoded)[0];
          if (local == other && peer == answerer)
            ++(*decoded)[1];
          if (local == requester && peer == answerer)
            ++(*decoded)[2];
        });
  });
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
  auto inject = [&](tos::adnl::AdnlNodeIdShort source,
                    tos::adnl::AdnlNodeIdShort destination) {
    td::Bits256 query_id, transfer_id;
    query_id.as_slice().fill(fill);
    transfer_id.as_slice().fill(248);
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
      td::actor::send_closure(h.adnl_, &tos::adnl::Adnl::send_message, source,
                              destination, std::move(packet));
    });
  };
  inject(h.buffered_, h.requester_);
  h.wait_for([&] { return (*decoded)[0] == 1; },
             "wrong-source response not decoded");
  h.run_for(0.1);
  CHECK(!result->has_value());
  inject(h.answerer_, h.buffered_);
  h.wait_for([&] { return (*decoded)[1] == 1; },
             "wrong-local response not decoded");
  h.run_for(0.1);
  CHECK(!result->has_value());
  inject(h.answerer_, h.requester_);
  h.wait_for([&] { return result->has_value() && (*decoded)[2] == 1; },
             "correct identity did not settle query");
  CHECK((*result)->is_ok());
  CHECK((*result)->ok().as_slice() == std::string(bytes, '*'));
  std::cout << "{\"wrong_remote_pending\":true,\"wrong_local_pending\":true,"
               "\"decoded_wrong_responses\":2,\"answer_bytes\":64,\"answer_"
               "fill\":42}\n";
}
