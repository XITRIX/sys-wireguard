#pragma once

#include <cstdint>
#include <string>
#include <utility>

namespace swg {

enum class ErrorCode : std::uint32_t {
  Ok = 0,
  NotFound,
  IoError,
  InvalidConfig,
  InvalidState,
  ParseError,
  ServiceUnavailable,
  Unsupported,
  AlreadyExists,
};

struct Error {
  ErrorCode code = ErrorCode::Ok;
  std::string message;

  [[nodiscard]] bool ok() const noexcept {
    return code == ErrorCode::Ok;
  }

  explicit operator bool() const noexcept {
    return !ok();
  }

  static Error None() {
    return {};
  }
};

inline Error MakeError(ErrorCode code, std::string message) {
  return Error{code, std::move(message)};
}

template <typename T>
struct Result {
  T value{};
  Error error{};

  [[nodiscard]] bool ok() const noexcept {
    return error.ok();
  }

  explicit operator bool() const noexcept {
    return ok();
  }

  static Result Success(T value) {
    return Result{std::move(value), Error::None()};
  }

  static Result Failure(Error error) {
    return Result{T{}, std::move(error)};
  }
};

template <typename T>
inline Result<T> MakeSuccess(T value) {
  return Result<T>::Success(std::move(value));
}

template <typename T>
inline Result<T> MakeFailure(ErrorCode code, std::string message) {
  return Result<T>::Failure(MakeError(code, std::move(message)));
}

}  // namespace swg
