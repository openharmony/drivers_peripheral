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
#include "v1_2/fingerprint_auth_interface_stub.h"
#include "v1_2/fingerprint_auth_interface_service.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_FINGERPRINT_AUTH_HDI

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace HDI {
namespace FingerprintAuth {
namespace {
constexpr uint32_t HDI_FINGERPRINT_AUTH_CODE_MIN = 2;
constexpr uint32_t HDI_FINGERPRINT_AUTH_CODE_MAX = 2;
const std::u16string FINGERPRINT_AUTH_INTERFACE_TOKEN = u"ohos.hdi.fingerprint_auth.v1_1.IFingerprintAuthInterface";
bool FingerprintAuthInterfaceStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }
    sptr<OHOS::HDI::FingerprintAuth::V1_2::IFingerprintAuthInterface> fingerprintAuth =
        OHOS::HDI::FingerprintAuth::V1_2::IFingerprintAuthInterface::Get(true);
    OHOS::HDI::FingerprintAuth::V1_2::FingerprintAuthInterfaceStub fingerprintAuthInterfaceStub(fingerprintAuth);
    for (uint32_t code = HDI_FINGERPRINT_AUTH_CODE_MIN; code <= HDI_FINGERPRINT_AUTH_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(FINGERPRINT_AUTH_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)fingerprintAuthInterfaceStub.OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(FINGERPRINT_AUTH_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)fingerprintAuthInterfaceStub.OnRemoteRequest(code, data, reply, optionAsync);
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
