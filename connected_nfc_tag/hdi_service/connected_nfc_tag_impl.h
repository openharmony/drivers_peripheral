/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_CONNECTEDNFCTAG_V1_0_CONNECTEDNFCTAGIMPL_H
#define OHOS_HDI_CONNECTEDNFCTAG_V1_0_CONNECTEDNFCTAGIMPL_H

#include <cstdint>
#include <string>

#include "v1_0/iconnected_nfc_tag.h"

namespace OHOS {
namespace HDI {
namespace ConnectedNfcTag {
namespace V1_0 {
class ConnectedNfcTagImpl {
public:
    ~ConnectedNfcTagImpl() = default;
    int32_t Init();
    int32_t Uninit();
    int32_t ReadNdefTag(std::string &ndefData);
    int32_t WriteNdefTag(std::string ndefData);
};
}  // namespace V1_0
}  // namespace ConnectedNfcTag
}  // namespace HDI
}  // namespace OHOS

#endif // OHOS_HDI_CONNECTEDNFCTAG_V1_0_CONNECTEDNFCTAGIMPL_H

