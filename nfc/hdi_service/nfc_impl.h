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

#ifndef OHOS_HDI_NFC_V1_1_NFCIMPL_H
#define OHOS_HDI_NFC_V1_1_NFCIMPL_H

#include "nfc_vendor_adaptions.h"
#include "v1_1/infc_interface.h"
#include "remote_death_recipient.h"

namespace OHOS {
namespace HDI {
namespace Nfc {
namespace V1_1 {
class NfcImpl : public INfcInterface {
public:
    NfcImpl();
    virtual ~NfcImpl();
    int32_t Open(const sptr<INfcCallback> &callbackObj, NfcStatus &status) override;
    int32_t CoreInitialized(const std::vector<uint8_t> &data, NfcStatus &status) override;
    int32_t Prediscover(NfcStatus &status) override;
    int32_t Write(const std::vector<uint8_t> &data, NfcStatus &status) override;
    int32_t ControlGranted(NfcStatus &status) override;
    int32_t PowerCycle(NfcStatus &status) override;
    int32_t Close(NfcStatus &status) override;
    int32_t Ioctl(NfcCommand cmd, const std::vector<uint8_t> &data, NfcStatus &status) override;
    int32_t IoctlWithResponse(NfcCommand cmd, const std::vector<uint8_t> &data, std::vector<uint8_t> &response,
        NfcStatus &status) override;
    int32_t GetVendorConfig(NfcVendorConfig &config, NfcStatus &status) override;
    int32_t DoFactoryReset(NfcStatus &status) override;
    int32_t Shutdown(NfcStatus &status) override;
private:
    void OnRemoteDied(const wptr<IRemoteObject> &object);
    int32_t AddNfcDeathRecipient(const sptr<INfcCallback> &callbackObj);
    int32_t RemoveNfcDeathRecipient(const sptr<INfcCallback> &callbackObj);

    NfcVendorAdaptions adaptor_;
    sptr<INfcCallback> callbacks_ = nullptr;
    sptr<RemoteDeathRecipient> remoteDeathRecipient_ = nullptr;
    std::mutex callbacksMutex_ {};
};
} // V1_1
} // Nfc
} // HDI
} // OHOS

#endif // OHOS_HDI_NFC_V1_1_NFCIMPL_H