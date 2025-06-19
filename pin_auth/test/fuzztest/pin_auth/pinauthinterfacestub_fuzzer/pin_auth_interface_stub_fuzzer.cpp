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

#include "pin_auth_interface_stub_fuzzer.h"
#include "parcel.h"
#include "iam_logger.h"
#include "pin_auth_hdi.h"
#include "v3_0/pin_auth_interface_stub.h"

#undef LOG_TAG
#define LOG_TAG "PIN_AUTH_HDI"

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace HDI {
namespace PinAuth {
namespace {
constexpr uint32_t HDI_PIN_AUTH_CODE_MIN = 2;
constexpr uint32_t HDI_PIN_AUTH_CODE_MAX = 2;
const std::u16string PIN_AUTH_INTERFACE_TOKEN = u"ohos.hdi.pin_auth.v2_1.IPinAuthInterface";
bool PinAuthInterfaceStubFuzzTest(const uint8_t *rawData, size_t size)
{
    IAM_LOGI("start");
    if (rawData == nullptr) {
        return false;
    }
    sptr<IPinAuthInterface> pinAuthInterface = IPinAuthInterface::Get(true);
    OHOS::HDI::PinAuth::V3_0::PinAuthInterfaceStub pinAuthInterfaceStub(pinAuthInterface);
    for (uint32_t code = HDI_PIN_AUTH_CODE_MIN; code <= HDI_PIN_AUTH_CODE_MAX; code++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption optionSync = MessageOption::TF_SYNC;
        MessageOption optionAsync = MessageOption::TF_ASYNC;
        // Sync
        data.WriteInterfaceToken(PIN_AUTH_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)pinAuthInterfaceStub.OnRemoteRequest(code, data, reply, optionSync);
        // Async
        data.WriteInterfaceToken(PIN_AUTH_INTERFACE_TOKEN);
        data.WriteBuffer(rawData, size);
        data.RewindRead(0);
        (void)pinAuthInterfaceStub.OnRemoteRequest(code, data, reply, optionAsync);
    }
    return true;
}
} // namespace
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::HDI::PinAuth::PinAuthInterfaceStubFuzzTest(data, size);
    return 0;
}
