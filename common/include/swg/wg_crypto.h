#pragma once

#include "swg/result.h"
#include "swg/wg_profile.h"

namespace swg {

Result<WireGuardKey> DeriveWireGuardPublicKey(const WireGuardKey& private_key);
Result<WireGuardKey> ComputeWireGuardSharedSecret(const WireGuardKey& private_key,
                                                  const WireGuardKey& peer_public_key);

}  // namespace swg