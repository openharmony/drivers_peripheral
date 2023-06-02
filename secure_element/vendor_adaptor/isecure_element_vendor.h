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

#ifndef I_SECURE_ELEMENT_VENDOR_H
#define I_SECURE_ELEMENT_VENDOR_H

#include "v1_0/isecure_element_interface.h"

namespace OHOS {
namespace HDI {
namespace SecureElement {
using OHOS::HDI::SecureElement::V1_0::ISecureElementCallback;
using OHOS::HDI::SecureElement::V1_0::SecureElementStatus;

class ISecureElementVendor {
public:
    virtual ~ISecureElementVendor() {}

    virtual int32_t init(const sptr<ISecureElementCallback>& clientCallback, SecureElementStatus& status) = 0;

    virtual int32_t getAtr(std::vector<uint8_t>& response) = 0;

    virtual int32_t isSecureElementPresent(bool& present) = 0;

    virtual int32_t openLogicalChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
        uint8_t& channelNumber, SecureElementStatus& status) = 0;

    virtual int32_t openBasicChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
        SecureElementStatus& status) = 0;

    virtual int32_t closeChannel(uint8_t channelNumber, SecureElementStatus& status) = 0;

    virtual int32_t transmit(const std::vector<uint8_t>& command, std::vector<uint8_t>& response,
        SecureElementStatus& status) = 0;

    virtual int32_t reset(SecureElementStatus& status) = 0;
};
} // SecureElement
} // HDI
} // OHOS
#endif /* I_SECURE_ELEMENT_VENDOR_H */
