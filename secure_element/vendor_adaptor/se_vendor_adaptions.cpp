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
#include "se_vendor_adaptions.h"

namespace OHOS {
namespace HDI {
namespace SecureElement {
SeVendorAdaptions::SeVendorAdaptions() {}

SeVendorAdaptions::~SeVendorAdaptions() {}

int32_t SeVendorAdaptions::init(const sptr<ISecureElementCallback>& clientCallback, SecureElementStatus& status)
{
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::getAtr(std::vector<uint8_t>& response)
{
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::isSecureElementPresent(bool& present)
{
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::openLogicalChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
    uint8_t& channelNumber, SecureElementStatus& status)
{
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::openBasicChannel(const std::vector<uint8_t>& aid, uint8_t p2, std::vector<uint8_t>& response,
    SecureElementStatus& status)
{
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::closeChannel(uint8_t channelNumber, SecureElementStatus& status)
{
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::transmit(const std::vector<uint8_t>& command, std::vector<uint8_t>& response,
    SecureElementStatus& status)
{
    return HDF_SUCCESS;
}

int32_t SeVendorAdaptions::reset(SecureElementStatus& status)
{
    return HDF_SUCCESS;
}

} // SecureElement
} // HDI
} // OHOS