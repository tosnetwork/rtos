// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "rldp2/rldp-connection-limits.h"
#include <iostream>
using namespace tos::rldp2;
auto identity(unsigned value) {
  td::Bits256 bits;
  bits.set_zero();
  for (unsigned i = 0; i < 4; ++i)
    bits.as_slice()[31 - i] = char(value >> (i * 8));
  return tos::adnl::AdnlNodeIdShort{bits};
}
unsigned number(tos::adnl::AdnlNodeIdShort id) {
  unsigned value = 0;
  for (unsigned i = 28; i < 32; ++i)
    value = value * 256 + static_cast<unsigned char>(id.as_slice()[i]);
  return value;
}
int main() {
  unsigned scenario, first, second, expiry1, expiry2, requester, refresh;
  while (std::cin >> scenario >> first >> second >> expiry1 >> expiry2 >>
         requester >> refresh) {
    CHECK(first + second == 4096 && scenario <= 5 && requester >= 1 &&
          requester <= 3);
    RldpTimeoutSet order;
    for (unsigned i = 0; i < first; ++i)
      record_connection(order, identity(1), identity(i),
                        td::Timestamp::at(expiry1));
    for (unsigned i = 0; i < second; ++i)
      record_connection(order, identity(2), identity(i),
                        td::Timestamp::at(expiry2));
    if (refresh)
      refresh_connection(order, identity(1), identity(0),
                         td::Timestamp::at(expiry1), td::Timestamp::at(30));
    auto victim = choose_eviction_victim(
        order, identity(requester), per_local_id_share(4096, order.size()));
    CHECK(victim);
    std::cout << scenario << ' ' << number(victim.value().local_id) << ' '
              << number(victim.value().peer_id) << '\n';
  }
}
