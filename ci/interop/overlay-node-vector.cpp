#include "tl-utils/tl-utils.hpp"
#include <iomanip>
#include <iostream>
#include <string>

static td::Bits256 repeated(unsigned char value) {
  td::Bits256 result;
  result.as_slice().fill(static_cast<char>(value));
  return result;
}

static void print(const char *name, const tos::tos_api::Object *object) {
  const auto bytes = tos::serialize_tl_object(object, true);
  std::cout << name << "=";
  for (unsigned char byte : bytes.as_slice()) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
  }
  std::cout << "\n";
}

int main() {
  auto to_sign = tos::tos_api::make_object<tos::tos_api::overlay_node_toSign>(
      tos::tos_api::make_object<tos::tos_api::adnl_id_short>(repeated(0x33)),
      repeated(0x22), 2, 1700000000);
  auto node = tos::tos_api::make_object<tos::tos_api::overlay_node>(
      tos::tos_api::make_object<tos::tos_api::pub_ed25519>(repeated(0x11)),
      repeated(0x22), 2, 1700000000, td::BufferSlice(std::string(64, '\x44')),
      tos::tos_api::make_object<tos::tos_api::overlay_emptyMemberCertificate>());
  print("to_sign", to_sign.get());
  print("node", node.get());
}
