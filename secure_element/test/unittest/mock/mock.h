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
#ifndef MOCK_VENDOR_ADAPTIONS_H
#define MOCK_VENDOR_ADAPTIONS_H

#include <string>
#include <gmock/gmock.h>
#include "secure_element_ca_proxy.h"

namespace OHOS {
namespace HDI {
namespace SecureElement {
class MockTee {
public:
    static void SetMockTee(MockTee &object)
    {
        obj = &object;
    }

    static void ResetMockTee()
    {
        obj = nullptr;
    }

    static MockTee *GetMockTee()
    {
        return obj;
    }
    MOCK_METHOD(int, VendorSecureElementCaOnStart, (), ());
    MOCK_METHOD(int, VendorSecureElementCaInit, (), ());
    MOCK_METHOD(int, VendorSecureElementCaUninit, (), ());
    MOCK_METHOD(int, VendorSecureElementCaGetAtr, (uint8_t *rsp, uint32_t *rspLen), ());
    MOCK_METHOD(int, VendorSecureElementCaOpenLogicalChannel, (uint8_t *aid, uint32_t len, uint8_t p2,
        uint8_t *rsp, uint32_t *rspLen, uint32_t *channelNum), ());
    MOCK_METHOD(int, VendorSecureElementCaOpenBasicChannel, (uint8_t *aid, uint32_t len, uint8_t *rsp,
        uint32_t *rspLen), ());
    MOCK_METHOD(int, VendorSecureElementCaCloseChannel, (uint32_t channelNum), ());
    MOCK_METHOD(int, VendorSecureElementCaTransmit, (uint8_t *cmd, uint32_t cmdLen, uint8_t *rsp,
        uint32_t *rspLen), ());
private:
    inline static MockTee *obj = nullptr;
};
} // SecureElement
} // HDI
} // OHOS

#endif // MOCK_VENDOR_ADAPTIONS_H
