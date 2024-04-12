/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "secure_element_interface_service.h"
#include <hdf_base.h>

#define HDF_LOG_TAG secure_element_interface_service

namespace OHOS {
namespace HDI {
namespace SecureElement {
namespace SimSecureElement {
namespace V1_0 {
extern "C" ISecureElementInterface *SecureElementInterfaceImplGetInstance(void)
{
    return new (std::nothrow) SecureElementInterfaceService();
}

int32_t SecureElementInterfaceService::init(
    const sptr<OHOS::HDI::SecureElement::SimSecureElement::V1_0::ISecureElementCallback>& clientCallback,
    OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status)
{
    return adaptor_.init(clientCallback, status);
}

int32_t SecureElementInterfaceService::getAtr(std::vector<uint8_t>& response)
{
    return adaptor_.getAtr(response);
}

int32_t SecureElementInterfaceService::isSecureElementPresent(bool& present)
{
    return adaptor_.isSecureElementPresent(present);
}

int32_t SecureElementInterfaceService::openLogicalChannel(const std::vector<uint8_t>& aid, uint8_t p2,
    std::vector<uint8_t>& response, uint8_t& channelNumber,
    OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status)
{
    return adaptor_.openLogicalChannel(aid, p2, response, channelNumber, status);
}

int32_t SecureElementInterfaceService::openBasicChannel(const std::vector<uint8_t>& aid, uint8_t p2,
    std::vector<uint8_t>& response, OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status)
{
    return adaptor_.openBasicChannel(aid, p2, response, status);
}

int32_t SecureElementInterfaceService::closeChannel(uint8_t channelNumber,
    OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status)
{
    return adaptor_.closeChannel(channelNumber, status);
}

int32_t SecureElementInterfaceService::transmit(const std::vector<uint8_t>& command, std::vector<uint8_t>& response,
    OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status)
{
    return adaptor_.transmit(command, response, status);
}

int32_t SecureElementInterfaceService::reset(
    OHOS::HDI::SecureElement::SimSecureElement::V1_0::SecureElementStatus& status)
{
    return adaptor_.reset(status);
}
} // V1_0
} // SimSecureElement
} // SecureElement
} // HDI
} // OHOS
