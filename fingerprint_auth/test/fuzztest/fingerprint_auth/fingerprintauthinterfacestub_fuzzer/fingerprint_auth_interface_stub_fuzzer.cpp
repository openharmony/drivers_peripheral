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

#include "fingerprint_auth_interface_stub_fuzzer.h"

#include "iam_logger.h"

#include "fingerprint_auth_hdi.h"

#undef LOG_TAG
#define LOG_TAG "FINGERPRINT_AUTH_IMPL"

#undef private

namespace OHOS {
namespace HDI {
namespace FingerprintAuth {
namespace {
constexpr uint32_t FINGERPRINT_AUTH_INTERFACE_STUB_CODE_MIN = 0;
constexpr uint32_t FINGERPRINT_AUTH_INTERFACE_STUB_CODE_MAX = 3;
constexpr uint32_t FINGERPRINT_AUTH_INTERFACE_STUB_CODE_MIN_V1_1 = 2;
const std::u16string FINGERPRINT_AUTH_INTERFACE_STUB_TOKEN_V1_0 =
    u"ohos.hdi.fingerprint_auth.v1_0.IFingerprintAuthInterface";
const std::u16string FINGERPRINT_AUTH_INTERFACE_STUB_TOKEN_V1_1 =
    u"ohos.hdi.fingerprint_auth.v2_0.IFingerprintAuthInterface";

bool FingerprintAuthInterfaceStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        IAM_LOGE("%{public}s:rawData is null.", __func__);
        return false;
    }
    sptr<IFingerprintAuthInterface> serviceImpl = IFingerprintAuthInterface::Get(true);
    if (serviceImpl == nullptr) {
        IAM_LOGE("%{public}s:get serviceImpl failed.", __func__);
        return false;
    }
    sptr<FingerprintAuthInterfaceStub> fingerprintAuthInterfaceStub = new FingerprintAuthInterfaceStub(serviceImpl);
    if (fingerprintAuthInterfaceStub == nullptr) {
        IAM_LOGE("%{public}s:new IFingerprintAuthInterfaceStub failed.", __func__);
        return false;
    }

    for (uint32_t code = FINGERPRINT_AUTH_INTERFACE_STUB_CODE_MIN; code < FINGERPRINT_AUTH_INTERFACE_STUB_CODE_MAX;
         code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        std::u16string FINGERPRINT_AUTH_INTERFACE_STUB_TOKEN;
        if (code < FINGERPRINT_AUTH_INTERFACE_STUB_CODE_MIN_V1_1) {
            FINGERPRINT_AUTH_INTERFACE_STUB_TOKEN = FINGERPRINT_AUTH_INTERFACE_STUB_TOKEN_V1_0;
        } else {
            FINGERPRINT_AUTH_INTERFACE_STUB_TOKEN = FINGERPRINT_AUTH_INTERFACE_STUB_TOKEN_V1_1;
        }
        // Sync
        data.WriteInterfaceToken(FINGERPRINT_AUTH_INTERFACE_STUB_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)fingerprintAuthInterfaceStub->OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(FINGERPRINT_AUTH_INTERFACE_STUB_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)fingerprintAuthInterfaceStub->OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}
} // namespace
} // namespace FingerprintAuth
} // namespace HDI
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::HDI::FingerprintAuth::FingerprintAuthInterfaceStubFuzzTest(data, size);
    return 0;
}
