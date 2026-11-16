// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#include "rldp2/RldpConnection.h"
#include <iostream>
int main() {
  unsigned count;
  CHECK(bool(std::cin >> count) && count == 257);
  tos::rldp2::RldpConnection connection{tos::rldp2::RldpPeerIdentity{}};
  for (unsigned i = 0; i < count; ++i) {
    tos::rldp2::TransferId id;
    id.set_zero();
    id.as_slice().copy_from(
        td::Slice(reinterpret_cast<const char *>(&i), sizeof(i)));
    connection.send(id, td::BufferSlice(std::string(64, '*')),
                    td::Timestamp::in(60.0));
  }
  CHECK(connection.outbound_transfer_count() == 256);
  std::cout << "{\"submitted\":257,\"retained\":256}\n";
}
