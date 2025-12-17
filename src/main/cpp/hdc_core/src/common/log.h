/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __H_HDC_LOG_H__
#define __H_HDC_LOG_H__

#include <cinttypes>

namespace Hdc {

namespace Base {
    void PrintLogEx(const char *functionName, int line, uint8_t logLevel, const char *msg, ...);
}

enum HdcLogLevel {
    HDC_LOG_OFF,
    HDC_LOG_FATAL,
    HDC_LOG_WARN,
    HDC_LOG_INFO,  // default
    HDC_LOG_DEBUG,
    HDC_LOG_ALL,
    HDC_LOG_VERBOSE,
    HDC_LOG_LAST = HDC_LOG_ALL,  // tail, not use
};

// Compatibility aliases for existing code using LOG_DEBUG etc.
// These are always defined within Hdc namespace to avoid conflicts with hilog/log.h
// When HDC_HILOG is defined, system hilog has its own LOG_DEBUG etc. in global namespace,
// but code using Hdc::LOG_DEBUG or within "using namespace Hdc" will use these.
constexpr HdcLogLevel LOG_OFF = HDC_LOG_OFF;
constexpr HdcLogLevel LOG_FATAL = HDC_LOG_FATAL;
constexpr HdcLogLevel LOG_WARN = HDC_LOG_WARN;
constexpr HdcLogLevel LOG_INFO = HDC_LOG_INFO;
constexpr HdcLogLevel LOG_DEBUG = HDC_LOG_DEBUG;
constexpr HdcLogLevel LOG_ALL = HDC_LOG_ALL;
constexpr HdcLogLevel LOG_VERBOSE = HDC_LOG_VERBOSE;
constexpr HdcLogLevel LOG_LAST = HDC_LOG_LAST;

}  // namespace Hdc

// WRITE_LOG macro - defined outside namespace to avoid ambiguity
// Uses Hdc:: prefix explicitly for log level constants
#ifdef IS_RELEASE_VERSION
#define WRITE_LOG(level, fmt, ...)   Hdc::Base::PrintLogEx(__FUNCTION__, __LINE__, static_cast<uint8_t>(Hdc::level), fmt, ##__VA_ARGS__)
#else
#define WRITE_LOG(level, fmt, ...)   Hdc::Base::PrintLogEx(__FILE_NAME__, __LINE__, static_cast<uint8_t>(Hdc::level), fmt, ##__VA_ARGS__)
#endif

namespace Hdc {

#ifndef HDC_HOST
#define WRITE_LOG_DAEMON(level, fmt, ...) WRITE_LOG(level, fmt, ##__VA_ARGS__)
#else
#define WRITE_LOG_DAEMON(level, fmt, ...)
#endif

#ifdef HDC_DEBUG
#define DEBUG_LOG(fmt, ...)   WRITE_LOG(LOG_DEBUG, fmt, ##__VA_ARGS__)
#else
#define DEBUG_LOG(fmt, ...)
#endif

}  // namespace Hdc
#endif  // __H_HDC_LOG_H__
