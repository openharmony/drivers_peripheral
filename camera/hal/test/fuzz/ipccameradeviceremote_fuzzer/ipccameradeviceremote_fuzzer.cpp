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

#include "ipccameradeviceremote_fuzzer.h"
#include "fuzz_base.h"

class IPCCameraDeviceRemoteFuzzer : public OHOS::Camera::CameraDeviceStub {
public:
    OHOS::Camera::CamRetCode GetStreamOperator(const OHOS::sptr<OHOS::Camera::IStreamOperatorCallback> &callback,
    OHOS::sptr<OHOS::Camera::IStreamOperator> &streamOperator) override
    {
        return OHOS::Camera::NO_ERROR;
    }
    OHOS::Camera::CamRetCode UpdateSettings(const std::shared_ptr<OHOS::Camera::CameraSetting> &settings) override
    {
        return OHOS::Camera::NO_ERROR;
    }
    OHOS::Camera::CamRetCode SetResultMode(const OHOS::Camera::ResultCallbackMode &mode) override
    {
        return OHOS::Camera::NO_ERROR;
    }
    OHOS::Camera::CamRetCode GetEnabledResults(std::vector<OHOS::Camera::MetaType> &results) override
    {
        return OHOS::Camera::NO_ERROR;
    }
    OHOS::Camera::CamRetCode EnableResult(const std::vector<OHOS::Camera::MetaType> &results) override
    {
        return OHOS::Camera::NO_ERROR;
    }
    OHOS::Camera::CamRetCode DisableResult(const std::vector<OHOS::Camera::MetaType> &results) override
    {
        return OHOS::Camera::NO_ERROR;
    }
    void Close() override {}
};

static uint32_t U32_AT(const uint8_t *ptr)
{
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}

static int32_t onRemoteRequest(uint32_t code, OHOS::MessageParcel &data)
{
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    IPCCameraDeviceRemoteFuzzer *IPCDevice = new IPCCameraDeviceRemoteFuzzer();
    auto ret = IPCDevice->OnRemoteRequest(code, data, reply, option);
    return ret;
}

static void IpcFuzzService(const uint8_t *data, size_t size)
{
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;
    OHOS::MessageParcel dataMessageParcel;
    if (size > sizeof(uint32_t)) {
        uint32_t code = U32_AT(data);
        if (code == 1) { // 1:code size
            return;
        }
        const uint8_t *number = data;
        number = number + sizeof(uint32_t);
        size_t length = size;
        length = length - sizeof(uint32_t);
        dataMessageParcel.WriteInterfaceToken(IPCCameraDeviceRemoteFuzzer::CameraDeviceStub::GetDescriptor());
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