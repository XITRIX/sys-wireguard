#include "swg/log.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace swg {
namespace {

const char* ToLabel(LogLevel level) {
  switch (level) {
    case LogLevel::Debug:
      return "DEBUG";
    case LogLevel::Info:
      return "INFO";
    case LogLevel::Warning:
      return "WARN";
    case LogLevel::Error:
      return "ERROR";
  }

  return "UNKNOWN";
}

std::string TimestampString() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t time = std::chrono::system_clock::to_time_t(now);
  std::tm local_time{};
#if defined(_WIN32)
  localtime_s(&local_time, &time);
#else
  local_time = *std::localtime(&time);
#endif

  std::ostringstream stream;
  stream << std::put_time(&local_time, "%Y-%m-%d %H:%M:%S");
  return stream.str();
}

}  // namespace

Logger& Logger::Instance() {
  static Logger logger;
  return logger;
}

Error Logger::Initialize(const std::filesystem::path& log_path) {
  std::scoped_lock lock(mutex_);

  if (initialized_ && log_path_ == log_path) {
    return Error::None();
  }

  std::error_code filesystem_error;
  std::filesystem::create_directories(log_path.parent_path(), filesystem_error);
  if (filesystem_error) {
    return MakeError(ErrorCode::IoError,
                     "failed to create log directory: " + filesystem_error.message());
  }

  if (stream_.is_open()) {
    stream_.close();
  }

  stream_.open(log_path, std::ios::app);
  if (!stream_.is_open()) {
    return MakeError(ErrorCode::IoError, "failed to open log file: " + log_path.string());
  }

  log_path_ = log_path;
  initialized_ = true;
  WriteLineUnlocked(LogLevel::Info, "logger", "logger initialized");
  return Error::None();
}

void Logger::Shutdown() {
  std::scoped_lock lock(mutex_);
  if (stream_.is_open()) {
    WriteLineUnlocked(LogLevel::Info, "logger", "logger shutdown");
    stream_.close();
  }
  initialized_ = false;
}

void Logger::Log(LogLevel level, std::string_view component, std::string_view message) {
  std::scoped_lock lock(mutex_);
  if (!initialized_) {
    return;
  }
  WriteLineUnlocked(level, component, message);
}

std::filesystem::path Logger::log_path() const {
  std::scoped_lock lock(mutex_);
  return log_path_;
}

void Logger::WriteLineUnlocked(LogLevel level, std::string_view component, std::string_view message) {
  const std::string line = TimestampString() + " [" + ToLabel(level) + "] [" + std::string(component) + "] " +
                           std::string(message);
  stream_ << line << '\n';
  stream_.flush();
  std::cerr << line << '\n';
}

void LogDebug(std::string_view component, std::string_view message) {
  Logger::Instance().Log(LogLevel::Debug, component, message);
}

void LogInfo(std::string_view component, std::string_view message) {
  Logger::Instance().Log(LogLevel::Info, component, message);
}

void LogWarning(std::string_view component, std::string_view message) {
  Logger::Instance().Log(LogLevel::Warning, component, message);
}

void LogError(std::string_view component, std::string_view message) {
  Logger::Instance().Log(LogLevel::Error, component, message);
}

}  // namespace swg
