#pragma once

#include <cstdarg>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <atomic>
#include <memory>
#include <mutex>

#ifdef __SWITCH__
#include "nxstl/mutex"
#endif

extern "C" void logvisorBp();

namespace logvisor {

void logvisorAbort();

#if _WIN32 && UNICODE
#define LOG_UCS2 1
#endif

/* True if ANSI color available */
extern bool XtermColor;

/**
 * @brief Severity level for log messages
 */
enum Level {
  Info,    /**< Non-error informative message */
  Warning, /**< Non-error warning message */
  Error,   /**< Recoverable error message */
  Fatal    /**< Non-recoverable error message (throws exception) */
};

/**
 * @brief Backend interface for receiving app-wide log events
 */
struct ILogger {
  virtual ~ILogger() {}
  virtual void report(const char* modName, Level severity, const char* format, va_list ap) = 0;
  virtual void report(const char* modName, Level severity, const wchar_t* format, va_list ap) = 0;
  virtual void reportSource(const char* modName, Level severity, const char* file, unsigned linenum, const char* format,
                            va_list ap) = 0;
  virtual void reportSource(const char* modName, Level severity, const char* file, unsigned linenum,
                            const wchar_t* format, va_list ap) = 0;
};

/**
 * @brief Terminate all child processes
 *
 * Implicitly called on abort condition.
 */
void KillProcessTree();

/**
 * @brief Assign calling thread a descriptive name
 * @param name Descriptive thread name
 */
void RegisterThreadName(const char* name);

/**
 * @brief Centralized logger vector
 *
 * All loggers added to this vector will receive reports as they occur
 */
extern std::vector<std::unique_ptr<ILogger>> MainLoggers;

/**
 * @brief Centralized error counter
 *
 * All submodules accumulate this value
 */
extern std::atomic_size_t ErrorCount;

/**
 * @brief Centralized frame index
 *
 * All log events include this as part of their timestamp if non-zero.
 * The default value is zero, the app is responsible for updating it
 * within its main loop.
 */
extern std::atomic_uint_fast64_t FrameIndex;

/**
 * @brief Centralized logging lock
 *
 * Ensures logging streams aren't written concurrently
 */
struct LogMutex {
  bool enabled = true;
  std::recursive_mutex mutex;
  ~LogMutex() { enabled = false; }
  std::unique_lock<std::recursive_mutex> lock() {
    if (enabled)
      return std::unique_lock<std::recursive_mutex>(mutex);
    else
      return std::unique_lock<std::recursive_mutex>();
  }
};
extern LogMutex _LogMutex;

/**
 * @brief Take a centralized lock for the logging output stream(s)
 * @return RAII mutex lock
 */
static inline std::unique_lock<std::recursive_mutex> LockLog() { return _LogMutex.lock(); }

extern uint64_t _LogCounter;

/**
 * @brief Get current count of logging events
 * @return Log Count
 */
static inline uint64_t GetLogCounter() { return _LogCounter; }

/**
 * @brief Restore centralized logger vector to default state (silent operation)
 */
static inline void UnregisterLoggers() { MainLoggers.clear(); }

/**
 * @brief Construct and register a real-time console logger singleton
 *
 * This will output to stderr on POSIX platforms and spawn a new console window on Windows.
 * If there's already a registered console logger, this is a no-op.
 */
void RegisterConsoleLogger();

/**
 * @brief Construct and register a file logger
 * @param filepath Path to write the file
 *
 * If there's already a file logger registered to the same file, this is a no-op.
 */
void RegisterFileLogger(const char* filepath);

/**
 * @brief Register signal handlers with system for common client exceptions
 */
void RegisterStandardExceptions();

#if _WIN32
/**
 * @brief Spawn an application-owned cmd.exe window for displaying console output
 */
void CreateWin32Console();
#endif

#if LOG_UCS2

/**
 * @brief Construct and register a file logger (wchar_t version)
 * @param filepath Path to write the file
 *
 * If there's already a file logger registered to the same file, this is a no-op.
 */
void RegisterFileLogger(const wchar_t* filepath);

#endif

/**
 * @brief This is constructed per-subsystem in a locally centralized fashon
 */
class Module {
  const char* m_modName;

public:
  Module(const char* modName) : m_modName(modName) {}

  /**
   * @brief Route new log message to centralized ILogger
   * @param severity Level of log report severity
   * @param format Standard printf-style format string
   */
  template <typename CharType>
  inline void report(Level severity, const CharType* format, ...) {
    if (MainLoggers.empty() && severity != Level::Fatal)
      return;
    va_list ap;
    va_start(ap, format);
    report(severity, format, ap);
    va_end(ap);
  }

  template <typename CharType>
  inline void report(Level severity, const CharType* format, va_list ap) {
    auto lk = LockLog();
    ++_LogCounter;
    if (severity == Fatal)
      RegisterConsoleLogger();
    for (auto& logger : MainLoggers) {
      va_list apc;
      va_copy(apc, ap);
      logger->report(m_modName, severity, format, apc);
      va_end(apc);
    }
    if (severity == Error || severity == Fatal)
      logvisorBp();
    if (severity == Fatal)
      logvisorAbort();
    else if (severity == Error)
      ++ErrorCount;
  }

  /**
   * @brief Route new log message with source info to centralized ILogger
   * @param severity Level of log report severity
   * @param file Source file name from __FILE__ macro
   * @param linenum Source line number from __LINE__ macro
   * @param format Standard printf-style format string
   */
  template <typename CharType>
  inline void reportSource(Level severity, const char* file, unsigned linenum, const CharType* format, ...) {
    if (MainLoggers.empty() && severity != Level::Fatal)
      return;
    va_list ap;
    va_start(ap, format);
    reportSource(severity, file, linenum, format, ap);
    va_end(ap);
  }

  template <typename CharType>
  inline void reportSource(Level severity, const char* file, unsigned linenum, const CharType* format, va_list ap) {
    auto lk = LockLog();
    ++_LogCounter;
    if (severity == Fatal)
      RegisterConsoleLogger();
    for (auto& logger : MainLoggers) {
      va_list apc;
      va_copy(apc, ap);
      logger->reportSource(m_modName, severity, file, linenum, format, apc);
      va_end(apc);
    }

    if (severity == Fatal)
      logvisorAbort();
    else if (severity == Error)
      ++ErrorCount;
  }
};

} // namespace logvisor
