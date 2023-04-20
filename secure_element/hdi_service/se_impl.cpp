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

namespace OHOS {
namespace HDI {
namespace SecureElement {
static sptr<ISecureElementCallback> g_callbackV1_0 = nullptr;

extern "C" ISecureElementInterface* SeImplGetInstance(void)
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
    if (clientCallback == nullptr) {
        HDF_LOGE("%{public}s: clientCallback is nullptr!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    g_callbackV1_0 = clientCallback;
    return HDF_SUCCESS;
}

int32_t SeImpl::getAtr(std::vector<uint8_t>& response)
{
    return HDF_SUCCESS;
}

int32_t SeImpl::isSecureElementPresent(bool& present)
{
    return HDF_SUCCESS;
}

int32_t SeImpl::openLogicalChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
    uint8_t& channelNumber, SecureElementStatus& status)
{
    return HDF_SUCCESS;
}

int32_t SeImpl::openBasicChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
    SecureElementStatus& status)
{
    return HDF_SUCCESS;
}

int32_t SeImpl::closeChannel(uint8_t channelNumber, SecureElementStatus& status)
{
    return HDF_SUCCESS;
}

int32_t SeImpl::transmit(const std::vector<uint8_t>& command, std::vector<uint8_t>& response,
    SecureElementStatus& status)
{
    return HDF_SUCCESS;
}

int32_t SeImpl::reset(SecureElementStatus& status)
{
    return HDF_SUCCESS;
}

} // SecureElement
} // HDI
} // OHOS
