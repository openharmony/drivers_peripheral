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
#include "mock.h"

namespace OHOS {
namespace HDI {
namespace SecureElement {

int SecureElementCaProxy::VendorSecureElementCaOnStart() const
{
    auto p = MockTee::GetMockTee();
    if (!p) {
        return 0;
    }
    return p->VendorSecureElementCaOnStart();
}

int SecureElementCaProxy::VendorSecureElementCaInit() const
{
    auto p = MockTee::GetMockTee();
    if (!p) {
        return 0;
    }
    return p->VendorSecureElementCaInit();
}

int SecureElementCaProxy::VendorSecureElementCaUninit() const
{
    auto p = MockTee::GetMockTee();
    if (!p) {
        return 0;
    }
    return p->VendorSecureElementCaUninit();
}

int SecureElementCaProxy::VendorSecureElementCaGetAtr(uint8_t *rsp, uint32_t *rspLen) const
{
    auto p = MockTee::GetMockTee();
    if (!p) {
        return 0;
    }
    return p->VendorSecureElementCaGetAtr(rsp, rspLen);
}

int SecureElementCaProxy::VendorSecureElementCaOpenLogicalChannel(uint8_t *aid, uint32_t len, uint8_t p2,
    uint8_t *rsp, uint32_t *rspLen, uint32_t *channelNum) const
{
    auto p = MockTee::GetMockTee();
    if (!p) {
        return 0;
    }
    return p->VendorSecureElementCaOpenLogicalChannel(aid, len, p2, rsp, rspLen, channelNum);
}

int SecureElementCaProxy::VendorSecureElementCaOpenBasicChannel(uint8_t *aid, uint32_t len, uint8_t *rsp,
    uint32_t *rspLen) const
{
    auto p = MockTee::GetMockTee();
    if (!p) {
        return 0;
    }
    return p->VendorSecureElementCaOpenBasicChannel(aid, len, rsp, rspLen);
}

int SecureElementCaProxy::VendorSecureElementCaCloseChannel(uint32_t channelNum) const
{
    auto p = MockTee::GetMockTee();
    if (!p) {
        return 0;
    }
    return p->VendorSecureElementCaCloseChannel(channelNum);
}

int SecureElementCaProxy::VendorSecureElementCaTransmit(uint8_t *cmd, uint32_t cmdLen, uint8_t *rsp,
    uint32_t *rspLen) const
{
    auto p = MockTee::GetMockTee();
    if (!p) {
        return 0;
    }
    return p->VendorSecureElementCaTransmit(cmd, cmdLen, rsp, rspLen);
}
SecureElementCaProxy::DynamicLoad::DynamicLoad(const std::string &lib) {}

SecureElementCaProxy::DynamicLoad::~DynamicLoad() {}

bool SecureElementCaProxy::DynamicLoad::LoadLib()
{
    return false;
}

bool SecureElementCaProxy::DynamicLoad::CloseLib()
{
    return false;
}
} // SecureElement
} // HDI
} // OHOS