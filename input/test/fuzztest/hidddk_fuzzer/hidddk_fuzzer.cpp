/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include "hdf_log.h"
#include "hidddk_fuzzer.h"
#include "v1_1/hid_ddk_stub.h"
#include "v1_1/ihid_ddk.h"

using namespace OHOS::HDI::Input::Ddk::V1_1;

namespace OHOS {
constexpr size_t THRESHOLD = 10;
constexpr int32_t OFFSET = 4;
constexpr int32_t ZERO_BIT = 0;
constexpr int32_t FIRST_BIT = 1;
constexpr int32_t SECOND_BIT = 2;
constexpr int32_t THIRD_BIT = 3;
constexpr int32_t ZERO_MOVE_LEN = 24;
constexpr int32_t FIRST_MOVE_LEN = 16;
constexpr int32_t SECOND_MOVE_LEN = 8;
const std::u16string HID_INTERFACE_TOKEN = u"ohos.hdi.input.ddk.v1_1.IHidDdk";

uint32_t Convert2Uint32(const uint8_t *ptr)
{
    if (ptr == nullptr) {
        HDF_LOGE("%{public}s: ptr is null", __func__);
        return 0;
    }
    /*
     * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
     * and the third digit no left
     */
    return (ptr[ZERO_BIT] << ZERO_MOVE_LEN) | (ptr[FIRST_BIT] << FIRST_MOVE_LEN) | (ptr[SECOND_BIT] <<
        SECOND_MOVE_LEN) | (ptr[THIRD_BIT]);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr) {
        HDF_LOGE("%{public}s: rawData is null", __func__);
        return false;
    }
    uint32_t code = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;
    size = size - OFFSET;

    MessageParcel data;
    data.WriteInterfaceToken(HID_INTERFACE_TOKEN);
    data.WriteBuffer(rawData, size);
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<OHOS::HDI::Input::Ddk::V1_1::IHidDdk> hidDdkInterface = OHOS::HDI::Input::Ddk::V1_1::IHidDdk::Get(false);
    if (hidDdkInterface == nullptr) {
        HDF_LOGE("%{public}s: get hidDdkInterface failed", __func__);
        return false;
    }
    sptr<OHOS::HDI::Input::Ddk::V1_1::HidDdkStub> hidDdk = new OHOS::HDI::Input::Ddk::V1_1::HidDdkStub(hidDdkInterface);
    if (hidDdk == nullptr) {
        HDF_LOGE("%{public}s: new hidDdk failed", __func__);
        return false;
    }
    hidDdk->OnRemoteRequest(code, data, reply, option);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

