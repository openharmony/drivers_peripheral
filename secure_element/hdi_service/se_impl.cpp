/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "se_impl.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <vector>

#define HDF_LOG_TAG hdf_se

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD000305

namespace OHOS {
namespace HDI {
namespace SecureElement {

extern "C" ISecureElementInterface *SecureElementInterfaceImplGetInstance(void)
{
    using OHOS::HDI::SecureElement::SeImpl;
    SeImpl* service = new (std::nothrow) SeImpl();
    if (service == nullptr) {
        return nullptr;
    }
    return service;
}

int32_t SeImpl::init(const sptr<ISecureElementCallback>& clientCallback, SecureElementStatus& status)
{
    return adaptor_.init(clientCallback, status);
}

int32_t SeImpl::getAtr(std::vector<uint8_t>& response)
{
    return adaptor_.getAtr(response);
}

int32_t SeImpl::isSecureElementPresent(bool& present)
{
    return adaptor_.isSecureElementPresent(present);
}

int32_t SeImpl::openLogicalChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
    uint8_t& channelNumber, SecureElementStatus& status)
{
    return adaptor_.openLogicalChannel(aid, p2, response, channelNumber, status);
}

int32_t SeImpl::openBasicChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
    SecureElementStatus& status)
{
    return adaptor_.openBasicChannel(aid, p2, response, status);
}

int32_t SeImpl::closeChannel(uint8_t channelNumber, SecureElementStatus& status)
{
    return adaptor_.closeChannel(channelNumber, status);
}

int32_t SeImpl::transmit(const std::vector<uint8_t>& command, std::vector<uint8_t>& response,
    SecureElementStatus& status)
{
    return adaptor_.transmit(command, response, status);
}

int32_t SeImpl::reset(SecureElementStatus& status)
{
    return adaptor_.reset(status);
}
} // SecureElement
} // HDI
} // OHOS
