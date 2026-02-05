#include "examples/test/test_util.h"

#include <cstddef>
#include <iomanip>
#include <ios>
#include <sstream>
#include <string>

HtoolInvocationMock* g_htool_invocation_mock = nullptr;

std::string print_hex_dump(const void* data_ptr, size_t size_bytes) {
  const unsigned char* p = static_cast<const unsigned char*>(data_ptr);
  std::stringstream ss;

  ss << std::hex << std::uppercase << std::setfill('0');

  ss << "0x";

  for (size_t i = 0; i < size_bytes; ++i) {
    ss << std::setw(2) << static_cast<int>(p[i]) << " ";
  }

  return ss.str();
}
