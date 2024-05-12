/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef CONNECTED_NFC_TAG_VENDOR_ADAPTER_H
#define CONNECTED_NFC_TAG_VENDOR_ADAPTER_H

#include "iconnected_nfc_tag_vendor.h"

namespace OHOS {
namespace HDI {
namespace ConnectedNfcTag {

using VendorGetChipType = const char *(*)();

struct NfcTagHalInterface {
    int32_t (*init)();
    int32_t (*unInit)();
    int32_t (*registerCallBack)(NfcTagChipEventCallbackT *callback);
    int32_t (*writeNdefData)(const uint8_t *writeData, uint32_t writeLen);
    int32_t (*readNdefData)(uint8_t *readData, uint32_t *readLen);
};

class ConnectedNfcTagVendorAdapter : public IConnectedNfcTagVendor {
public:
    ConnectedNfcTagVendorAdapter();
    ~ConnectedNfcTagVendorAdapter() override;
    int32_t Init() override;
    int32_t UnInit() override;
    int32_t RegisterCallBack(NfcTagChipEventCallbackT *callback) override;
    int32_t WriteNdefData(const std::vector<uint8_t>& ndefData) override;
    int32_t ReadNdefData(std::vector<uint8_t>& ndefData) override;
private:
    int32_t GetInterfaceFromHal();
private:
    void *halHandle; // handle of nfc hal so
    NfcTagHalInterface infHandle;
};

} // ConnectedNfcTag
} // HDI
} // OHOS

#endif // CONNECTED_NFC_TAG_VENDOR_ADAPTER_H
