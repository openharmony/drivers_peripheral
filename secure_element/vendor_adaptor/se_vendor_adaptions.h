/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef SE_VENDOR_ADAPTIONS_H
#define SE_VENDOR_ADAPTIONS_H

#include "isecure_element_vendor.h"

#include "remote_death_recipient.h"

namespace OHOS {
namespace HDI {
namespace SecureElement {
class SeVendorAdaptions : public ISecureElementVendor {
public:
    SeVendorAdaptions();
    ~SeVendorAdaptions() override;

    int32_t init(const sptr<ISecureElementCallback>& clientCallback, SecureElementStatus& status) override;

    int32_t getAtr(std::vector<uint8_t>& response) override;

    int32_t isSecureElementPresent(bool& present) override;

    int32_t openLogicalChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
        uint8_t& channelNumber, SecureElementStatus& status) override;

    int32_t openBasicChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
        SecureElementStatus& status) override;

    int32_t closeChannel(uint8_t channelNumber, SecureElementStatus& status) override;

    int32_t transmit(const std::vector<uint8_t>& command, std::vector<uint8_t>& response,
        SecureElementStatus& status) override;

    int32_t reset(SecureElementStatus& status) override;

    SecureElementStatus getStatusBySW(uint8_t sw1, uint8_t sw2) const;

private:
    void OnRemoteDied(const wptr<IRemoteObject> &object);
    int32_t AddSecureElementDeathRecipient(const sptr<ISecureElementCallback> &callbackObj);
    int32_t RemoveSecureElementDeathRecipient(const sptr<ISecureElementCallback> &callbackObj);

    sptr<RemoteDeathRecipient> remoteDeathRecipient_ = nullptr;
};
} // SecureElement
} // HDI
} // OHOS

#endif // SE_VENDOR_ADAPTIONS_H
