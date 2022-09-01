/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_NFC_V1_0_NFCIMPL_H
#define OHOS_HDI_NFC_V1_0_NFCIMPL_H

#include "nfc_vendor_adaptions.h"
#include "v1_0/infc_interface.h"

namespace OHOS {
namespace HDI {
namespace Nfc {
namespace V1_0 {
class NfcImpl : public INfcInterface {
public:
    virtual ~NfcImpl() {}
    int32_t Open(const sptr<INfcCallback> &callbackObj, NfcStatus &status) override;
    int32_t CoreInitialized(const std::vector<uint8_t> &data, NfcStatus &status) override;
    int32_t Prediscover(NfcStatus &status) override;
    int32_t Write(const std::vector<uint8_t> &data, NfcStatus &status) override;
    int32_t ControlGranted(NfcStatus &status) override;
    int32_t PowerCycle(NfcStatus &status) override;
    int32_t Close(NfcStatus &status) override;
    int32_t Ioctl(NfcCommand cmd, const std::vector<uint8_t> &data, NfcStatus &status) override;
private:
    NfcVendorAdaptions adaptor_;
};
} // V1_0
} // Nfc
} // HDI
} // OHOS

#endif // OHOS_HDI_NFC_V1_0_NFCIMPL_H