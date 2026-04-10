#pragma once

#include "swg/ipc_codec.h"

namespace swg {

class IClientTransport {
 public:
  virtual ~IClientTransport() = default;

  virtual Result<ByteBuffer> Invoke(const ByteBuffer& request_bytes) const = 0;
};

}  // namespace swg
