#pragma once

#include <cstddef>

#include "swg/result.h"
#include "swg/wg_profile.h"

namespace swg {

Result<WireGuardKey> DeriveWireGuardPublicKey(const WireGuardKey& private_key);
Result<WireGuardKey> ComputeWireGuardSharedSecret(const WireGuardKey& private_key,
                                                  const WireGuardKey& peer_public_key);
Error GenerateRandomBytes(std::uint8_t* output, std::size_t size);

}  // namespace swg
