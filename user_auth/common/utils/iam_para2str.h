/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef IAM_PARA2STR_H
#define IAM_PARA2STR_H

#include <iomanip>
#include <map>
#include <sstream>
#include <string>

namespace OHOS {
namespace UserIam {
namespace Common {
using namespace std;
const int32_t MASK_WIDTH = 4;
static inline std::string GetMaskedString(uint16_t val)
{
    std::ostringstream ss;
    ss << "0xXXXX" << std::setfill('0') << std::setw(MASK_WIDTH) << std::hex << val;
    return ss.str();
}

#define GET_MASKED_STRING(val) OHOS::UserIam::Common::GetMaskedString(static_cast<uint16_t>(val))

static inline std::string GetPointerNullStateString(void *p)
{
    return p == nullptr ? "null" : "non-null";
}

} // namespace Common
} // namespace UserIam
} // namespace OHOS

#endif // IAM_PARA2STR_H