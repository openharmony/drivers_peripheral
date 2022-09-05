/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "ipccameradevicecallback_fuzzer.h"
#include "fuzz_base.h"
#include "types.h"

using namespace OHOS::Camera;
class IPCCameraDeviceCallbackFuzzer : public CameraDeviceCallbackStub {
public:
    void OnError(ErrorType type, int32_t errorCode) override {}
    void OnResult(uint64_t timestamp, const std::shared_ptr<CameraMetadata> &result) override {}
};

static uint32_t U32_AT(const uint8_t *ptr)
{
    // 24, 16 and 8 respectively represent the shift lengths of ptr under different indexes (0, 1 and 2)
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}

static int32_t onRemoteRequest(uint32_t code, OHOS::MessageParcel &data)
{
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    IPCCameraDeviceCallbackFuzzer *IPCDeviceCallback;
    auto ret = IPCDeviceCallback->OnRemoteRequest(code, data, reply, option);
    return ret;
}

static void IpcFuzzService(const uint8_t *data, size_t size)
{
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    OHOS::MessageParcel dataMessageParcel;
    uint32_t code = U32_AT(data);
    const uint8_t *number = data;
    number = number + sizeof(uint32_t);
    if (size > sizeof(uint32_t)) {
        if (code == 1) { // 1:code size
            return;
        }
        size_t length = size;
        length = length - sizeof(uint32_t);
        dataMessageParcel.WriteInterfaceToken(OHOS::Camera::CameraDeviceCallbackStub::GetDescriptor());
        dataMessageParcel.WriteBuffer(number, length);
        dataMessageParcel.RewindRead(0);
        onRemoteRequest(code, dataMessageParcel);
    }
}

static void OnRemoteRequestFunc(const uint8_t *data, size_t size)
{
    IpcFuzzService(data, size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OnRemoteRequestFunc(data, size);
    return 0;
}