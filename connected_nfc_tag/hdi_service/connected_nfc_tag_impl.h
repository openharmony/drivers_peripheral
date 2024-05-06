/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef CONNECTED_NFC_TAG_IMPL_H
#define CONNECTED_NFC_TAG_IMPL_H

#include <cstdint>
#include <string>

#include "v1_1/iconnected_nfc_tag.h"
#include "connected_nfc_tag_vendor_adapter.h"

namespace OHOS {
namespace HDI {
namespace ConnectedNfcTag {
namespace V1_1 {
class ConnectedNfcTagImpl : public OHOS::HDI::ConnectedNfcTag::V1_1::IConnectedNfcTag {
public:
    ConnectedNfcTagImpl() = default;
    virtual ~ConnectedNfcTagImpl() = default;

    int32_t RegisterCallBack(
        const sptr<OHOS::HDI::ConnectedNfcTag::V1_1::IConnectedNfcTagCallback>& callbackObj) override;
    int32_t Init() override;
    int32_t Uninit() override;
    int32_t ReadNdefData(std::vector<uint8_t> &ndefData) override;
    int32_t WriteNdefData(const std::vector<uint8_t>& ndefData) override;
    int32_t ReadNdefTag(std::string &ndefData) override;
    int32_t WriteNdefTag(const std::string &ndefData) override;

private:
    ConnectedNfcTagVendorAdapter adapter;
};
}  // namespace V1_1
}  // namespace ConnectedNfcTag
}  // namespace HDI
}  // namespace OHOS

#endif // CONNECTED_NFC_TAG_IMPL_H
