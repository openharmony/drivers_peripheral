/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "input_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include "hdf_log.h"
#include "v1_0/input_interfaces_stub.h"

using namespace OHOS::HDI::Input::V1_0;

namespace OHOS {
constexpr size_t THRESHOLD = 10;
constexpr int32_t OFFSET = 4;
const std::u16string INPUT_INTERFACE_TOKEN = u"ohos.hdi.input.v1_0.IInputInterfaces";

uint32_t Convert2Uint32(const uint8_t* ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    /*
     * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
     * and the third digit no left
     */
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }
    uint32_t code = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;
    size = size - OFFSET;

    MessageParcel data;
    data.WriteInterfaceToken(INPUT_INTERFACE_TOKEN);
    data.WriteBuffer(rawData, size);
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    sptr<IInputInterfaces> g_inputInterface = IInputInterfaces::Get(false);
    if (g_inputInterface == nullptr) {
        HDF_LOGE("%{public}s:IInputInterfaces::Get() failed.", __func__);
        return false;
    }
    sptr<InputInterfacesStub> inputInterface = new InputInterfacesStub(g_inputInterface);
    if (inputInterface == nullptr) {
        HDF_LOGE("%{public}s:new InputInterfacesStub failed.", __func__);
        return false;
    }
    inputInterface->OnRemoteRequest(code, data, reply, option);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

