#include "swg/wg_crypto.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <mutex>
#include <sstream>
#include <string_view>

#include <psa/crypto.h>

namespace swg {
namespace {

class ScopedPsaKey {
 public:
  ScopedPsaKey() = default;

  explicit ScopedPsaKey(mbedtls_svc_key_id_t key_id) : key_id_(key_id) {}

  ~ScopedPsaKey() {
    if (key_id_ != MBEDTLS_SVC_KEY_ID_INIT) {
      psa_destroy_key(key_id_);
    }
  }

  ScopedPsaKey(const ScopedPsaKey&) = delete;
  ScopedPsaKey& operator=(const ScopedPsaKey&) = delete;

  ScopedPsaKey(ScopedPsaKey&& other) noexcept : key_id_(other.key_id_) {
    other.key_id_ = MBEDTLS_SVC_KEY_ID_INIT;
  }

  ScopedPsaKey& operator=(ScopedPsaKey&& other) noexcept {
    if (this != &other) {
      if (key_id_ != MBEDTLS_SVC_KEY_ID_INIT) {
        psa_destroy_key(key_id_);
      }

      key_id_ = other.key_id_;
      other.key_id_ = MBEDTLS_SVC_KEY_ID_INIT;
    }

    return *this;
  }

  [[nodiscard]] mbedtls_svc_key_id_t get() const {
    return key_id_;
  }

 private:
  mbedtls_svc_key_id_t key_id_ = MBEDTLS_SVC_KEY_ID_INIT;
};

std::once_flag g_psa_crypto_once;
psa_status_t g_psa_crypto_status = PSA_ERROR_BAD_STATE;

psa_status_t EnsurePsaCrypto() {
  std::call_once(g_psa_crypto_once, []() {
    g_psa_crypto_status = psa_crypto_init();
  });
  return g_psa_crypto_status;
}

ErrorCode MapPsaStatus(psa_status_t status) {
  switch (status) {
    case PSA_SUCCESS:
      return ErrorCode::Ok;
    case PSA_ERROR_NOT_SUPPORTED:
      return ErrorCode::Unsupported;
    case PSA_ERROR_NOT_PERMITTED:
    case PSA_ERROR_INVALID_ARGUMENT:
      return ErrorCode::InvalidConfig;
    case PSA_ERROR_BAD_STATE:
      return ErrorCode::InvalidState;
    case PSA_ERROR_BUFFER_TOO_SMALL:
    case PSA_ERROR_INSUFFICIENT_MEMORY:
      return ErrorCode::IoError;
    default:
      return ErrorCode::ServiceUnavailable;
  }
}

std::string DescribePsaStatus(psa_status_t status) {
  switch (status) {
    case PSA_SUCCESS:
      return "PSA_SUCCESS";
    case PSA_ERROR_NOT_SUPPORTED:
      return "PSA_ERROR_NOT_SUPPORTED";
    case PSA_ERROR_NOT_PERMITTED:
      return "PSA_ERROR_NOT_PERMITTED";
    case PSA_ERROR_INVALID_ARGUMENT:
      return "PSA_ERROR_INVALID_ARGUMENT";
    case PSA_ERROR_BAD_STATE:
      return "PSA_ERROR_BAD_STATE";
    case PSA_ERROR_BUFFER_TOO_SMALL:
      return "PSA_ERROR_BUFFER_TOO_SMALL";
    case PSA_ERROR_INSUFFICIENT_MEMORY:
      return "PSA_ERROR_INSUFFICIENT_MEMORY";
    case PSA_ERROR_COMMUNICATION_FAILURE:
      return "PSA_ERROR_COMMUNICATION_FAILURE";
    case PSA_ERROR_CORRUPTION_DETECTED:
      return "PSA_ERROR_CORRUPTION_DETECTED";
    default: {
      std::ostringstream stream;
      stream << "psa_status=" << status;
      return stream.str();
    }
  }
}

Error MakePsaError(psa_status_t status, std::string_view operation) {
  return MakeError(MapPsaStatus(status), std::string(operation) + " failed: " + DescribePsaStatus(status));
}

psa_key_attributes_t MakeX25519PrivateAttributes() {
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
  psa_set_key_bits(&attributes, 255);
  psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
  return attributes;
}

bool IsZeroKey(const WireGuardKey& key) {
  return std::all_of(key.bytes.begin(), key.bytes.end(), [](std::uint8_t byte) {
    return byte == 0;
  });
}

Result<ScopedPsaKey> ImportPrivateKey(const WireGuardKey& private_key) {
  const psa_status_t init_status = EnsurePsaCrypto();
  if (init_status != PSA_SUCCESS) {
    return Result<ScopedPsaKey>::Failure(MakePsaError(init_status, "psa_crypto_init"));
  }

  psa_key_attributes_t attributes = MakeX25519PrivateAttributes();
  mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
  const psa_status_t import_status =
      psa_import_key(&attributes, private_key.bytes.data(), private_key.bytes.size(), &key_id);
  psa_reset_key_attributes(&attributes);
  if (import_status != PSA_SUCCESS) {
    return Result<ScopedPsaKey>::Failure(MakePsaError(import_status, "psa_import_key"));
  }

  return MakeSuccess(ScopedPsaKey(key_id));
}

}  // namespace

Result<WireGuardKeyPair> GenerateWireGuardKeyPair() {
  const psa_status_t init_status = EnsurePsaCrypto();
  if (init_status != PSA_SUCCESS) {
    return Result<WireGuardKeyPair>::Failure(MakePsaError(init_status, "psa_crypto_init"));
  }

  psa_key_attributes_t attributes = MakeX25519PrivateAttributes();
  mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
  const psa_status_t generate_status = psa_generate_key(&attributes, &key_id);
  psa_reset_key_attributes(&attributes);
  if (generate_status != PSA_SUCCESS) {
    return Result<WireGuardKeyPair>::Failure(MakePsaError(generate_status, "psa_generate_key"));
  }

  ScopedPsaKey generated_key(key_id);
  std::array<std::uint8_t,
             PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY), 255)>
      private_key_bytes{};
  size_t private_key_size = 0;
  psa_status_t export_status =
      psa_export_key(generated_key.get(), private_key_bytes.data(), private_key_bytes.size(), &private_key_size);
  if (export_status != PSA_SUCCESS) {
    return Result<WireGuardKeyPair>::Failure(MakePsaError(export_status, "psa_export_key"));
  }

  std::array<std::uint8_t,
             PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY), 255)>
      public_key_bytes{};
  size_t public_key_size = 0;
  export_status = psa_export_public_key(generated_key.get(), public_key_bytes.data(), public_key_bytes.size(),
                                        &public_key_size);
  if (export_status != PSA_SUCCESS) {
    return Result<WireGuardKeyPair>::Failure(MakePsaError(export_status, "psa_export_public_key"));
  }

  if (private_key_size != kWireGuardKeySize || public_key_size != kWireGuardKeySize) {
    return MakeFailure<WireGuardKeyPair>(ErrorCode::InvalidConfig,
                                         "psa generated an unexpected X25519 key size");
  }

  WireGuardKeyPair key_pair{};
  std::copy_n(private_key_bytes.begin(), key_pair.private_key.bytes.size(), key_pair.private_key.bytes.begin());
  std::copy_n(public_key_bytes.begin(), key_pair.public_key.bytes.size(), key_pair.public_key.bytes.begin());
  return MakeSuccess(key_pair);
}

Error GenerateRandomBytes(std::uint8_t* output, std::size_t size) {
  const psa_status_t init_status = EnsurePsaCrypto();
  if (init_status != PSA_SUCCESS) {
    return MakePsaError(init_status, "psa_crypto_init");
  }

  const psa_status_t random_status = psa_generate_random(output, size);
  if (random_status != PSA_SUCCESS) {
    return MakePsaError(random_status, "psa_generate_random");
  }

  return Error::None();
}

Result<WireGuardKey> DeriveWireGuardPublicKey(const WireGuardKey& private_key) {
  const Result<ScopedPsaKey> imported_key = ImportPrivateKey(private_key);
  if (!imported_key.ok()) {
    return MakeFailure<WireGuardKey>(imported_key.error.code, imported_key.error.message);
  }

  std::array<std::uint8_t,
             PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY), 255)>
      public_key_bytes{};
  size_t public_key_size = 0;
  const psa_status_t export_status =
      psa_export_public_key(imported_key.value.get(), public_key_bytes.data(), public_key_bytes.size(),
                            &public_key_size);
  if (export_status != PSA_SUCCESS) {
    return MakeFailure<WireGuardKey>(MapPsaStatus(export_status),
                                     MakePsaError(export_status, "psa_export_public_key").message);
  }

  if (public_key_size != kWireGuardKeySize) {
    return MakeFailure<WireGuardKey>(ErrorCode::InvalidConfig,
                                     "psa_export_public_key returned an unexpected X25519 public key size");
  }

  WireGuardKey public_key{};
  std::copy_n(public_key_bytes.begin(), public_key.bytes.size(), public_key.bytes.begin());
  return MakeSuccess(std::move(public_key));
}

Result<WireGuardKey> ComputeWireGuardSharedSecret(const WireGuardKey& private_key,
                                                  const WireGuardKey& peer_public_key) {
  const Result<ScopedPsaKey> imported_key = ImportPrivateKey(private_key);
  if (!imported_key.ok()) {
    return MakeFailure<WireGuardKey>(imported_key.error.code, imported_key.error.message);
  }

  std::array<std::uint8_t,
             PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY), 255)>
      shared_secret_bytes{};
  size_t shared_secret_size = 0;
  const psa_status_t agreement_status =
      psa_raw_key_agreement(PSA_ALG_ECDH, imported_key.value.get(), peer_public_key.bytes.data(),
                            peer_public_key.bytes.size(), shared_secret_bytes.data(), shared_secret_bytes.size(),
                            &shared_secret_size);
  if (agreement_status != PSA_SUCCESS) {
    return MakeFailure<WireGuardKey>(MapPsaStatus(agreement_status),
                                     MakePsaError(agreement_status, "psa_raw_key_agreement").message);
  }

  if (shared_secret_size != kWireGuardKeySize) {
    return MakeFailure<WireGuardKey>(ErrorCode::InvalidConfig,
                                     "psa_raw_key_agreement returned an unexpected X25519 shared secret size");
  }

  WireGuardKey shared_secret{};
  std::copy_n(shared_secret_bytes.begin(), shared_secret.bytes.size(), shared_secret.bytes.begin());
  if (IsZeroKey(shared_secret)) {
    return MakeFailure<WireGuardKey>(ErrorCode::InvalidConfig,
                                     "X25519 shared secret must not be all zero for a valid peer public key");
  }

  return MakeSuccess(std::move(shared_secret));
}

}  // namespace swg