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

// Stub implementation for HdcServer in NAPI library mode
// Server functionality is not needed when running as a client library

#ifdef HDC_NAPI_LIBRARY

#include "server.h"

namespace Hdc {

// PullupServer is not supported in NAPI library mode
// The app should connect to an existing HDC server instead of starting one
bool HdcServer::PullupServer(const char *listenString)
{
    (void)listenString;
    WRITE_LOG(LOG_WARN, "PullupServer not supported in NAPI library mode");
    return false;
}

}  // namespace Hdc

#endif  // HDC_NAPI_LIBRARY
