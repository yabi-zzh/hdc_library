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
/*
 * HarmonyOS NAPI Library adaptation
 * This version is adapted for HarmonyOS application environment
 * where system APIs like init_reboot.h and parameter.h are not available.
 */
#include "system_depend.h"
#include "base.h"

// HarmonyOS 应用环境不支持系统级 API
// 使用简化实现

namespace Hdc {
namespace SystemDepend {

bool GetDevItem(const char *key, string &out, const char *preDefine)
{
    // HarmonyOS 应用环境中无法直接访问系统参数
    // 返回预定义值或空字符串
    if (preDefine != nullptr) {
        out = preDefine;
        return true;
    }
    out = "";
    return false;
}

}  // namespace SystemDepend
}  // namespace Hdc
