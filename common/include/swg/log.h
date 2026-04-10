#pragma once

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string_view>

#include "swg/result.h"

namespace swg {

enum class LogLevel {
  Debug = 0,
  Info,
  Warning,
  Error,
};

class Logger {
 public:
  static Logger& Instance();

  Error Initialize(const std::filesystem::path& log_path);
  void Shutdown();
  void Log(LogLevel level, std::string_view component, std::string_view message);
  [[nodiscard]] std::filesystem::path log_path() const;

 private:
  Logger() = default;

  bool EnsureStreamOpenUnlocked();
  void WriteLineUnlocked(LogLevel level, std::string_view component, std::string_view message);

  mutable std::mutex mutex_;
  std::ofstream stream_;
  std::filesystem::path log_path_;
  bool initialized_ = false;
};

void LogDebug(std::string_view component, std::string_view message);
void LogInfo(std::string_view component, std::string_view message);
void LogWarning(std::string_view component, std::string_view message);
void LogError(std::string_view component, std::string_view message);

}  // namespace swg
